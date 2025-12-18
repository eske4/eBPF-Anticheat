cmake_minimum_required(VERSION 3.25.1)

set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)

# Enforce Linux
project(
  eBPFA
  VERSION 1.0.0
  LANGUAGES C CXX
  DESCRIPTION "An anticheat focused on eBPF")

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/")

add_compile_options(-Wall -Wextra)

include(Build)
include(Environment)
include(Packages)
include(Compiler)
include(BPF)
include(CPM)

add_subdirectory(src)
add_subdirectory(app)
add_subdirectory(test)
