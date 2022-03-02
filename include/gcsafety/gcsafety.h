#ifndef GCSAFETY_GCSAFETY_H
#define GCSAFETY_GCSAFETY_H

namespace llvm {
class StringRef;
}

namespace clang {

namespace tidy {
class ClangTidyCheckFactories;
class ClangTidyModule;
class ClangTidyCheck;
} // namespace tidy
namespace ast_matchers {}
} // namespace clang

namespace gcsafety {
using clang::tidy::ClangTidyCheck;
using clang::tidy::ClangTidyCheckFactories;
using clang::tidy::ClangTidyModule;
using namespace clang;
using llvm::StringRef;

namespace ast_matchers = clang::ast_matchers;
} // namespace gcsafety
#endif
