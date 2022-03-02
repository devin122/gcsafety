#include "AllocationAnnotationCheck.h"
#include "GCAnnotation.h"

#include "clang/AST/AST.h"
#include "clang/AST/ASTContext.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/Sema/ParsedAttr.h"
#include "clang/Sema/Sema.h"
#include "clang/Sema/SemaDiagnostic.h"

using namespace clang::ast_matchers;

namespace gcsafety {

void AllocationAnnotationCheck::registerMatchers(MatchFinder *Finder) {
  auto GCCallMatcher =
      callExpr(callee(functionDecl(isAllocatingFunction()).bind("callee")))
          .bind("callsite");
  auto check2 = functionDecl(forEachDescendant(GCCallMatcher),
                             unless(isAllocatingFunction()))
                    .bind("containing-func");
  Finder->addMatcher(check2, this);
}

void AllocationAnnotationCheck::check(const MatchFinder::MatchResult &Result) {

  const auto *MatchedCaller =
      Result.Nodes.getNodeAs<FunctionDecl>("containing-func");
  const auto *MatchedCallSite = Result.Nodes.getNodeAs<CallExpr>("callsite");
  const auto *MatchedCallee = Result.Nodes.getNodeAs<FunctionDecl>("callee");

  if (!MatchedCallSite || !MatchedCaller || !MatchedCallee) {
    llvm::errs() << "Internal error: I don't think this can actually happen\n";
    return;
  }

  diag(MatchedCallSite->getBeginLoc(),
       "Non allocating function %0, calls allocating function %1")

      << MatchedCaller << MatchedCallee;
  diag(MatchedCallee->getBeginLoc(), "%0 declared here", DiagnosticIDs::Note);
}
} // namespace gcsafety
