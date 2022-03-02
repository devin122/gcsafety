
#ifndef GCSAFETY_POINTER_INVALIDATION_CHECK_H
#define GCSAFETY_POINTER_INVALIDATION_CHECK_H

#include "clang-tidy/ClangTidyCheck.h"
#include "gcsafety/gcsafety.h"

namespace gcsafety {

/// Check for types which inherit from a heap allocated class but arent
/// annotated
class PointerInvalidationCheck : public clang::tidy::ClangTidyCheck {
public:
  PointerInvalidationCheck(llvm::StringRef Name, clang::tidy::ClangTidyContext *Context)
      : ClangTidyCheck(Name, Context) {}
  void registerMatchers(ast_matchers::MatchFinder *Finder) override;
  void check(const ast_matchers::MatchFinder::MatchResult &Result) override;
};

} // namespace gcsafety

#endif // GCSAFETY_POINTER_INVALIDATION_CHECK_H
