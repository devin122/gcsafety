
add_library(gcsafety_checks STATIC
    AllocationAnnotationCheck.cpp
    InheritHeapClassCheck.cpp
    PointerInvalidationCheck.cpp
)
target_link_libraries(gcsafety_checks PRIVATE clangTidyUtils)

target_include_directories(gcsafety_checks PUBLIC . ${CMAKE_SOURCE_DIR}/include)
target_precompile_headers(gcsafety_checks PRIVATE
    <clang-tidy/ClangTidyCheck.h>
    <clang/AST/AST.h>
    <clang/AST/ASTContext.h>
    <clang/ASTMatchers/ASTMatchFinder.h>
    <clang/Sema/ParsedAttr.h>
    <clang/Sema/Sema.h>
    <clang/Sema/SemaDiagnostic.h>
)

