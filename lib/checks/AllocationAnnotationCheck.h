
#ifndef GCSAFETY_ALLOCATION_ANNOTATION_CHECK_H
#define GCSAFETY_ALLOCATION_ANNOTATION_CHECK_H

#include "gcsafety/gcsafety.h"
#include "clang-tidy/ClangTidyCheck.h"


namespace gcsafety {

/// Check for functions which call a function which may allocate,
/// but aren't annotated as such
class AllocationAnnotationCheck : public ClangTidyCheck {
public:
  AllocationAnnotationCheck(StringRef Name, clang::tidy::ClangTidyContext *Context)
      : ClangTidyCheck(Name, Context) {}
  void registerMatchers(ast_matchers::MatchFinder *Finder) override;
  void check(const ast_matchers::MatchFinder::MatchResult &Result) override;
};

} // namespace gcsafety


#endif
