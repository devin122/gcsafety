cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(gc-safety
    LANGUAGES CXX
    VERSION 0.1.0)

find_package(Clang REQUIRED)

# -fcolor-diagnostics

set(CMAKE_CXX_FLAGS "-fno-exceptions -fno-rtti  -fdiagnostics-color ${CMAKE_CXX_FLAGS}")
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED true)

list(PREPEND CMAKE_MODULE_PATH "${CLANG_CMAKE_DIR}" "${LLVM_CMAKE_DIR}")
#include(AddClang)
include(AddLLVM)

include_directories(${CLANG_INCLUDE_DIRS} ${LLVM_INCLUDE_DIRS})

add_subdirectory(lib)
add_subdirectory(extern)
add_subdirectory(test)
#add_subdirectory(plugin)
#add_subdirectory(tool)
