
#ifndef GCSAFETY_INHERIT_HEAP_CLASS_CHECK_H
#define GCSAFETY_INHERIT_HEAP_CLASS_CHECK_H

#include "clang-tidy/ClangTidyCheck.h"
#include "gcsafety/gcsafety.h"

namespace gcsafety {

/// Check for types which inherit from a heap allocated class but arent
/// annotated
class InheritHeapClassCheck : public ClangTidyCheck {
public:
  InheritHeapClassCheck(StringRef Name, clang::tidy::ClangTidyContext *Context)
      : ClangTidyCheck(Name, Context) {}
  void registerMatchers(ast_matchers::MatchFinder *Finder) override;
  void check(const ast_matchers::MatchFinder::MatchResult &Result) override;
};

} // namespace gcsafety


#endif // LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_GCSAFETY_INHERIT_HEAP_CLASS_CHECK_H
