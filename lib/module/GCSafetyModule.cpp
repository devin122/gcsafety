#include "AllocationAnnotationCheck.h"
#include "InheritHeapClassCheck.h"
#include "PointerInvalidationCheck.h"

#include "clang-tidy/ClangTidy.h"
#include "clang-tidy/ClangTidyModule.h"
#include "clang-tidy/ClangTidyModuleRegistry.h"

namespace gcsafety {

class GCSafetyModule : public ClangTidyModule {
public:
  void addCheckFactories(ClangTidyCheckFactories &CheckFactories) override {
    CheckFactories.registerCheck<InheritHeapClassCheck>(
        "gcsafe-inherit-heap-class");
    CheckFactories.registerCheck<PointerInvalidationCheck>(
        "gcsafe-pointer-invalidation");
    CheckFactories.registerCheck<AllocationAnnotationCheck>(
        "gcsafe-allocation-annotation");
  }
};

} // namespace gcsafety

// Register the GCSafetyModule using this statically initialized variable.
static clang::tidy::ClangTidyModuleRegistry::Add<gcsafety::GCSafetyModule>
    X("gcsafe-module", "Adds GC safety checks.");

// This anchor is used to force the linker to link in the generated object file
// and thus register the MiscModule.
volatile int GCSafetyModuleAnchorSource = 0;
