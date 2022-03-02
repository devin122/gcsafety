# GC Safety checks
TODO: add documentation
## Requirements:
- LLVM/Clang 13
## Building:
Project builds like any standard CMake project. However most distro don't ship all the required files
as part of their LLVM/Clang packages. Instead the recommended solution is to download an official release
tarball from https://github.com/llvm/llvm-project/releases/tag/llvmorg-13.0.0, and use `-DCMAKE_PREFIX_PATH=`
to point to the extracted files.