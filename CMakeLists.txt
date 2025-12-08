cmake_minimum_required(VERSION 3.25.1)

# Enforce Linux
project(
  AeBPF
  VERSION 1.0.0
  LANGUAGES C CXX
  DESCRIPTION "An anticheat focused on eBPF")

# Enforce clang
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED True)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON) # auto complete for nvim

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/")

include(Build)
include(Environment)
include(CPM)
include(Packages)

add_subdirectory(src)
add_subdirectory(app)
