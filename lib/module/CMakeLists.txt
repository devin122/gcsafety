add_executable(gcsafetyModule  GCSafetyModule.cpp main.cpp)
target_link_libraries(gcsafetyModule   PRIVATE clangTidyMain gcsafety_checks)

target_precompile_headers(gcsafetyModule PRIVATE
	<clang-tidy/ClangTidy.h>
    <clang-tidy/ClangTidyCheck.h>
	<clang-tidy/ClangTidyModule.h>
	<clang-tidy/ClangTidyModuleRegistry.h>
)
