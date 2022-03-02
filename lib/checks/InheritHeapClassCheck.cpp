// gcsafety-inherit-heap-class
#include "InheritHeapClassCheck.h"
#include "GCAnnotation.h"

#include "clang/AST/AST.h"
#include "clang/AST/ASTContext.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/Sema/ParsedAttr.h"
#include "clang/Sema/Sema.h"
#include "clang/Sema/SemaDiagnostic.h"
using namespace clang::ast_matchers;
using namespace clang;

namespace gcsafety {

void InheritHeapClassCheck::registerMatchers(MatchFinder *Finder) {
  Finder->addMatcher(
      cxxRecordDecl(
          hasAnyBase(
              hasType(cxxRecordDecl(isHeapAllocated()).bind("HeapAllocated"))),
          unless(isHeapAllocated()))
          .bind("Derrived"),
      this);
}

void InheritHeapClassCheck::check(const MatchFinder::MatchResult &Result) {
  // FIXME: Add callback implementation.

  const auto *MatchedDecl = Result.Nodes.getNodeAs<CXXRecordDecl>("Derrived");
  if (!MatchedDecl) {
    llvm::errs() << "DEBUG inherit-heap-class-check failed to match (I don't "
                    "think this can happen\n";
    return;
  }

  const auto *ParentDecl =
      Result.Nodes.getNodeAs<CXXRecordDecl>("HeapAllocated");

  diag(MatchedDecl->getLocation(), "a non heap allocated class class %0 "
                                   "inherits from a heap allocated class %1")
      << MatchedDecl->getName() << (ParentDecl ? ParentDecl->getName() : "");
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
