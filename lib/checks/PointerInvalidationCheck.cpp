#include "PointerInvalidationCheck.h"
#include "GCAnnotation.h"

#include "clang-tidy/utils/ExprSequence.h"
#include "GCAnnotation.h"
#include "gcsafety/gcsafety.h"
#include "clang/AST/AST.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/ExprConcepts.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/AST/ASTTypeTraits.h"
#include "clang/Analysis/CFG.h"
#include "clang/Sema/ParsedAttr.h"
#include "clang/Sema/Sema.h"
#include "clang/Sema/SemaDiagnostic.h"

using namespace clang::ast_matchers;
using namespace clang::tidy::utils;

namespace gcsafety {
/*
AST_MATCHER(Decl, mayAllocate) {
  auto *attr = Node.getAttr<AnnotateAttr>();
  if (attr == nullptr) {
    return false;
  }
  return (attr->getAnnotation() == "gc::may_allocate");
}*/

namespace {
AST_MATCHER(Expr, hasUnevaluatedContext) {
  if (isa<CXXNoexceptExpr>(Node) || isa<RequiresExpr>(Node))
    return true;
  if (const auto *UnaryExpr = dyn_cast<UnaryExprOrTypeTraitExpr>(&Node)) {
    switch (UnaryExpr->getKind()) {
    case UETT_SizeOf:
    case UETT_AlignOf:
      return true;
    default:
      return false;
    }
  }
  if (const auto *TypeIDExpr = dyn_cast<CXXTypeidExpr>(&Node))
    return !TypeIDExpr->isPotentiallyEvaluated();
  return false;
}

/// Contains information about a use-after-move.
struct UseAfterMove {
  // The DeclRefExpr that constituted the use of the object.
  const DeclRefExpr *DeclRef;

  // Is the order in which the move and the use are evaluated undefined?
  bool EvaluationOrderUndefined;
};

/// Finds uses of a variable after a move (and maintains state required by the
/// various internal helper functions).
class UseAfterMoveFinder {
public:
  UseAfterMoveFinder(ASTContext *TheContext);

  // Within the given function body, finds the first use of 'MovedVariable' that
  // occurs after 'MovingCall' (the expression that performs the move). If a
  // use-after-move is found, writes information about it to 'TheUseAfterMove'.
  // Returns whether a use-after-move was found.
  bool find(Stmt *FunctionBody, const Expr *MovingCall,
            const ValueDecl *MovedVariable, UseAfterMove *TheUseAfterMove);

private:
  bool findInternal(const CFGBlock *Block, const Expr *MovingCall,
                    const ValueDecl *MovedVariable,
                    UseAfterMove *TheUseAfterMove);
  void getUsesAndReinits(const CFGBlock *Block, const ValueDecl *MovedVariable,
                         llvm::SmallVectorImpl<const DeclRefExpr *> *Uses,
                         llvm::SmallPtrSetImpl<const Stmt *> *Reinits);
  void getDeclRefs(const CFGBlock *Block, const Decl *MovedVariable,
                   llvm::SmallPtrSetImpl<const DeclRefExpr *> *DeclRefs);
  void getReinits(const CFGBlock *Block, const ValueDecl *MovedVariable,
                  llvm::SmallPtrSetImpl<const Stmt *> *Stmts,
                  llvm::SmallPtrSetImpl<const DeclRefExpr *> *DeclRefs);

  ASTContext *Context;
  std::unique_ptr<ExprSequence> Sequence;
  std::unique_ptr<StmtToBlockMap> BlockMap;
  llvm::SmallPtrSet<const CFGBlock *, 8> Visited;
};

} // namespace

// Matches nodes that are
// - Part of a decltype argument or class template argument (we check this by
//   seeing if they are children of a TypeLoc), or
// - Part of a function template argument (we check this by seeing if they are
//   children of a DeclRefExpr that references a function template).
// DeclRefExprs that fulfill these conditions should not be counted as a use or
// move.
static StatementMatcher inDecltypeOrTemplateArg() {
  return anyOf(hasAncestor(typeLoc()),
               hasAncestor(declRefExpr(
                   to(functionDecl(ast_matchers::isTemplateInstantiation())))),
               hasAncestor(expr(hasUnevaluatedContext())));
}

UseAfterMoveFinder::UseAfterMoveFinder(ASTContext *TheContext)
    : Context(TheContext) {}

bool UseAfterMoveFinder::find(Stmt *FunctionBody, const Expr *GCCall,
                              const ValueDecl *MovedVariable,
                              UseAfterMove *TheUseAfterGC) {
  // Generate the CFG manually instead of through an AnalysisDeclContext because
  // it seems the latter can't be used to generate a CFG for the body of a
  // lambda.
  //
  // We include implicit and temporary destructors in the CFG so that
  // destructors marked [[noreturn]] are handled correctly in the control flow
  // analysis. (These are used in some styles of assertion macros.)
  CFG::BuildOptions Options;
  Options.AddImplicitDtors = true;
  Options.AddTemporaryDtors = true;
  std::unique_ptr<CFG> TheCFG =
      CFG::buildCFG(nullptr, FunctionBody, Context, Options);
  if (!TheCFG) {
    llvm::errs() << "DEBUG: failed to build cfg?\n";
    return false;
  }

  Sequence =
      std::make_unique<ExprSequence>(TheCFG.get(), FunctionBody, Context);
  BlockMap = std::make_unique<StmtToBlockMap>(TheCFG.get(), Context);
  Visited.clear();

  const CFGBlock *Block = BlockMap->blockContainingStmt(GCCall);
  if (!Block)
    return false;

  return findInternal(Block, GCCall, MovedVariable, TheUseAfterGC);
}

bool UseAfterMoveFinder::findInternal(const CFGBlock *Block, const Expr *GCCall,
                                      const ValueDecl *MovedVariable,
                                      UseAfterMove *TheUseAfterMove) {
  if (Visited.count(Block))
    return false;

  // Mark the block as visited (except if this is the block containing the
  // gc call and it's being visited the first time).
  if (!GCCall)
    Visited.insert(Block);

  // Get all uses and reinits in the block.
  llvm::SmallVector<const DeclRefExpr *, 1> Uses;
  llvm::SmallPtrSet<const Stmt *, 1> Reinits;
  getUsesAndReinits(Block, MovedVariable, &Uses, &Reinits);

  // Ignore all reinitializations where the GC call potentially comes after the
  // reinit.
  llvm::SmallVector<const Stmt *, 1> ReinitsToDelete;
  for (const Stmt *Reinit : Reinits) {
    if (GCCall && Sequence->potentiallyAfter(GCCall, Reinit))
      ReinitsToDelete.push_back(Reinit);
  }
  for (const Stmt *Reinit : ReinitsToDelete) {
    Reinits.erase(Reinit);
  }

  // Find all uses that potentially come after the GC.
  for (const DeclRefExpr *Use : Uses) {
    if (!GCCall || Sequence->potentiallyAfter(Use, GCCall)) {
      // Does the use have a saving reinit? A reinit is saving if it definitely
      // comes before the use, i.e. if there's no potential that the reinit is
      // after the use.
      bool HaveSavingReinit = false;
      for (const Stmt *Reinit : Reinits) {
        if (!Sequence->potentiallyAfter(Reinit, Use))
          HaveSavingReinit = true;
      }

      if (!HaveSavingReinit) {
        TheUseAfterMove->DeclRef = Use;

        // Is this a use-after-gc that depends on order of evaluation?
        // This is the case if the gc call potentially comes after the use (and
        // we already know that use potentially comes after the gc call, which
        // taken together tells us that the ordering is unclear).
        TheUseAfterMove->EvaluationOrderUndefined =
            GCCall != nullptr && Sequence->potentiallyAfter(GCCall, Use);

        return true;
      }
    }
  }

  // If the object wasn't reinitialized, call ourselves recursively on all
  // successors.
  if (Reinits.empty()) {
    for (const auto &Succ : Block->succs()) {
      if (Succ && findInternal(Succ, nullptr, MovedVariable, TheUseAfterMove))
        return true;
    }
  }

  return false;
}

void UseAfterMoveFinder::getUsesAndReinits(
    const CFGBlock *Block, const ValueDecl *MovedVariable,
    llvm::SmallVectorImpl<const DeclRefExpr *> *Uses,
    llvm::SmallPtrSetImpl<const Stmt *> *Reinits) {
  llvm::SmallPtrSet<const DeclRefExpr *, 1> DeclRefs;
  llvm::SmallPtrSet<const DeclRefExpr *, 1> ReinitDeclRefs;

  getDeclRefs(Block, MovedVariable, &DeclRefs);
  getReinits(Block, MovedVariable, Reinits, &ReinitDeclRefs);

  // All references to the variable that aren't reinitializations are uses.
  Uses->clear();
  for (const DeclRefExpr *DeclRef : DeclRefs) {
    if (!ReinitDeclRefs.count(DeclRef))
      Uses->push_back(DeclRef);
  }

  // Sort the uses by their occurrence in the source code.
  std::sort(Uses->begin(), Uses->end(),
            [](const DeclRefExpr *D1, const DeclRefExpr *D2) {
              return D1->getExprLoc() < D2->getExprLoc();
            });
}

/*
bool isStandardSmartPointer(const ValueDecl *VD) {
  const Type *TheType = VD->getType().getNonReferenceType().getTypePtrOrNull();
  if (!TheType)
    return false;

  const CXXRecordDecl *RecordDecl = TheType->getAsCXXRecordDecl();
  if (!RecordDecl)
    return false;

  const IdentifierInfo *ID = RecordDecl->getIdentifier();
  if (!ID)
    return false;

  StringRef Name = ID->getName();
  if (Name != "unique_ptr" && Name != "shared_ptr" && Name != "weak_ptr")
    return false;

  return RecordDecl->getDeclContext()->isStdNamespace();
}
*/
void UseAfterMoveFinder::getDeclRefs(
    const CFGBlock *Block, const Decl *MovedVariable,
    llvm::SmallPtrSetImpl<const DeclRefExpr *> *DeclRefs) {
  DeclRefs->clear();
  for (const auto &Elem : *Block) {
    Optional<CFGStmt> S = Elem.getAs<CFGStmt>();
    if (!S)
      continue;

    auto addDeclRefs = [this, Block,
                        DeclRefs](const ArrayRef<BoundNodes> Matches) {
      for (const auto &Match : Matches) {
        const auto *DeclRef = Match.getNodeAs<DeclRefExpr>("declref");
#if 0
        const auto *Operator = Match.getNodeAs<CXXOperatorCallExpr>("operator");
        if (DeclRef && BlockMap->blockContainingStmt(DeclRef) == Block) {
          // Ignore uses of a standard smart pointer that don't dereference the
          // pointer.
          if (Operator || !isStandardSmartPointer(DeclRef->getDecl())) {
            DeclRefs->insert(DeclRef);
          }
        }
#endif
        // I think this is an accurate translation of above (assuming we dont
        // care about smart pointers
        if (DeclRef && BlockMap->blockContainingStmt(DeclRef) == Block) {
          DeclRefs->insert(DeclRef);
        }
      }
    };

    auto DeclRefMatcher = declRefExpr(hasDeclaration(equalsNode(MovedVariable)),
                                      unless(inDecltypeOrTemplateArg()))
                              .bind("declref");

    addDeclRefs(
        match(traverse(clang::TK_AsIs, findAll(DeclRefMatcher)),
              *S->getStmt(), *Context));
    addDeclRefs(match(findAll(cxxOperatorCallExpr(
                                  hasAnyOverloadedOperatorName("*", "->", "[]"),
                                  hasArgument(0, DeclRefMatcher))
                                  .bind("operator")),
                      *S->getStmt(), *Context));
  }
}

void UseAfterMoveFinder::getReinits(
    const CFGBlock *Block, const ValueDecl *MovedVariable,
    llvm::SmallPtrSetImpl<const Stmt *> *Stmts,
    llvm::SmallPtrSetImpl<const DeclRefExpr *> *DeclRefs) {
  auto DeclRefMatcher =
      declRefExpr(hasDeclaration(equalsNode(MovedVariable))).bind("declref");

  // Matches different types of reinitialization.
  // my much more conservative re-init checker
  // TODO: possibly want to add more things here, especially for wrapped
  // pointers
   // foo
  auto ReinitMatcher =
      stmt(anyOf(
               // Assignment. In addition to the overloaded assignment operator,
               // test for built-in assignment as well, since template functions
               // may be instantiated to use std::move() on built-in types.
               binaryOperator(hasOperatorName("="), hasLHS(DeclRefMatcher)),
               cxxOperatorCallExpr(hasOverloadedOperatorName("="),
                                   hasArgument(0, DeclRefMatcher)),
               // Declaration. We treat this as a type of reinitialization too,
               // so we don't need to treat it separately.
               declStmt(hasDescendant(equalsNode(MovedVariable)))))
          .bind("reinit");
#if 0
  auto ReinitMatcher =
      stmt(anyOf(
               // Assignment. In addition to the overloaded assignment operator,
               // test for built-in assignment as well, since template functions
               // may be instantiated to use std::move() on built-in types.
               binaryOperator(hasOperatorName("="), hasLHS(DeclRefMatcher)),
               cxxOperatorCallExpr(hasOverloadedOperatorName("="),
                                   hasArgument(0, DeclRefMatcher)),
               // Declaration. We treat this as a type of reinitialization too,
               // so we don't need to treat it separately.
               declStmt(hasDescendant(equalsNode(MovedVariable))),
               // clear() and assign() on standard containers.
               cxxMemberCallExpr(
                   on(expr(DeclRefMatcher, StandardContainerTypeMatcher)),
                   // To keep the matcher simple, we check for assign() calls
                   // on all standard containers, even though only vector,
                   // deque, forward_list and list have assign(). If assign()
                   // is called on any of the other containers, this will be
                   // flagged by a compile error anyway.
                   callee(cxxMethodDecl(hasAnyName("clear", "assign")))),
               // reset() on standard smart pointers.
               cxxMemberCallExpr(
                   on(expr(DeclRefMatcher, StandardSmartPointerTypeMatcher)),
                   callee(cxxMethodDecl(hasName("reset")))),
               // Methods that have the [[clang::reinitializes]] attribute.
               cxxMemberCallExpr(
                   on(DeclRefMatcher),
                   callee(cxxMethodDecl(hasAttr(clang::attr::Reinitializes)))),
               // Passing variable to a function as a non-const pointer.
			   // TODO: I maybe want to flag this
               callExpr(forEachArgumentWithParam(
                   unaryOperator(hasOperatorName("&"),
                                 hasUnaryOperand(DeclRefMatcher))//,
                   unless(parmVarDecl(hasType(pointsTo(isConstQualified())))))),
               // Passing variable to a function as a non-const lvalue reference
               // (unless that function is std::move()).
			   /*
               callExpr(forEachArgumentWithParam(
                            traverse(ast_type_traits::TK_AsIs, DeclRefMatcher),
                            unless(parmVarDecl(hasType(
                                references(qualType(isConstQualified())))))),
                        unless(callee(functionDecl(hasName("::std::move")))))*/))
          .bind("reinit");
#endif

  Stmts->clear();
  DeclRefs->clear();
  for (const auto &Elem : *Block) {
    Optional<CFGStmt> S = Elem.getAs<CFGStmt>();
    if (!S)
      continue;

    SmallVector<BoundNodes, 1> Matches =
        match(findAll(ReinitMatcher), *S->getStmt(), *Context);

    for (const auto &Match : Matches) {
      const auto *TheStmt = Match.getNodeAs<Stmt>("reinit");
      const auto *TheDeclRef = Match.getNodeAs<DeclRefExpr>("declref");
      if (TheStmt && BlockMap->blockContainingStmt(TheStmt) == Block) {
        Stmts->insert(TheStmt);

        // We count DeclStmts as reinitializations, but they don't have a
        // DeclRefExpr associated with them -- so we need to check 'TheDeclRef'
        // before adding it to the set.
        if (TheDeclRef)
          DeclRefs->insert(TheDeclRef);
      }
    }
  }
}

static void emitDiagnostic(const Expr *MovingCall, const VarDecl *MoveArg,
                           const UseAfterMove &Use, clang::tidy::ClangTidyCheck *Check,
                           ASTContext *Context) {
  SourceLocation UseLoc = Use.DeclRef->getExprLoc();
  SourceLocation MoveLoc = MovingCall->getExprLoc();

  Check->diag(UseLoc, "'%0' used after a possible GC") << MoveArg->getName();
  Check->diag(MoveLoc, "possible gc occurrs here", DiagnosticIDs::Note);
  if (Use.EvaluationOrderUndefined) {
    Check->diag(UseLoc,
                "the use and gc are unsequenced, i.e. there is no guarantee "
                "about the order in which they are evaluated",
                DiagnosticIDs::Note);
  } else if (UseLoc < MoveLoc /*|| Use.DeclRef == MoveArg*/) {
    Check->diag(UseLoc, "the use happens in a later loop iteration than the gc",
                DiagnosticIDs::Note);
  }
}

void PointerInvalidationCheck::registerMatchers(MatchFinder *Finder) {
  // FIXME: Add matchers.
  // Finder->addMatcher(callexpr(calee(hasAttr("hustle::may_allocate"))).bind("X"),
  //                   this);
  /*auto GCCallMatcher =
      callexpr(callee(functionDecl(mayAllocate)),
               anyOf(hasAncestor(lambdaExpr().bind("containing-lambda")),
                     hasAncestor(functionDecl().bind("containing-func"))))
        */
  // Matches a call to a function which may allocate
  auto HeapPointer =
      anyOf(hasType(pointsTo(isHeapAllocated())), hasType(isHeapPointer()));
  auto GCCallMatcher =
      callExpr(callee(functionDecl(isAllocatingFunction()).bind("callee")))
          .bind("callsite");
  auto ManagedLocal = varDecl(HeapPointer).bind("heap-var");
  auto matcher2 = functionDecl(forEachDescendant(GCCallMatcher),
                               forEachDescendant(ManagedLocal))
                      .bind("containing-func");

  //.bind("call-move"); // TODO rename when I'm sure its not ref'd
#if 0
  Finder->addMatcher(
      functionDecl(
          hasBody(
              callExpr(callee(functionDecl(isAllocatingFunction()))).bind("callsite")))
          .bind("function"),
      this);
#endif
  // Finder->addMatcher(matcher2, this);
  Finder->addMatcher(matcher2, this);
  // Finder->addMatcher(varDecl(), this);
}

void PointerInvalidationCheck::check(const MatchFinder::MatchResult &Result) {
  // FIXME: Add callback implementation.

  const auto *ContainingLambda =
      Result.Nodes.getNodeAs<LambdaExpr>("containing-lambda");
  if (ContainingLambda) {
    llvm::errs() << "DEBUG: can't handle lambda, bailing.\n";
    return;
  }
  const auto *ContainingFunc =
      Result.Nodes.getNodeAs<FunctionDecl>("containing-func");
  const auto *CallMove = Result.Nodes.getNodeAs<CallExpr>("callsite");
  const auto *HeapVar = Result.Nodes.getNodeAs<VarDecl>("heap-var");

  UseAfterMoveFinder finder(Result.Context);
  UseAfterMove Use;
  if (finder.find(ContainingFunc->getBody(), CallMove, HeapVar, &Use))
    emitDiagnostic(CallMove, HeapVar, Use, this, Result.Context);
  /*
const auto *HeapVar = Result.Nodes.getNodeAs<VarDecl>("heap-var");
// const auto *CallMove = Result.Nodes.getNodeAs<CallExpr>("callsite");

llvm::errs() << "Function: " << ContainingFunc->getName() << "\n";
llvm::errs() << HeapVar->getName() << "/n";
*/

  // Stmt *FunctionBody = ContainingFunc->getBody();

  // TODO we could probably check the params/locals as part of the ast matcher
  // TODO at some point it would be nice to refactor the code to handle multiple
  // values better

  /*
  if (!MatchedDecl->getIdentifier() ||
      MatchedDecl->getName().startswith("awesome_"))
    return;
  diag(MatchedDecl->getLocation(), "function %0 is insufficiently awesome")
      << MatchedDecl;
  diag(MatchedDecl->getLocation(), "insert 'awesome'", DiagnosticIDs::Note)
      << FixItHint::CreateInsertion(MatchedDecl->getLocation(), "awesome_");
          */
}
} // namespace gcsafety
