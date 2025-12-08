message(STATUS "======================================")
message(STATUS "Performing environment check")
message(STATUS "======================================")

# Ensures it's on Linux
if(NOT UNIX)
  message(FATAL_ERROR "AeBPF only supports Linux.")
endif()
message(STATUS "Environment is Linux")
# ##############################################################################

# Detect arch
file(READ "/etc/os-release" OS_RELEASE_CONTENT)

if(OS_RELEASE_CONTENT MATCHES "ID=arch")
  message(STATUS "Detected Arch Linux")
else()
  message(FATAL_ERROR "AeBPF only supports Arch Linux")
endif()
message(STATUS "Found Arch Linux")
# ##############################################################################

# Check for CLang compiler
find_program(CLANG_EXECUTABLE clang)

if(NOT CLANG_EXECUTABLE)
  message(
    FATAL_ERROR
      "clang is required to build eBPF programs, but was not found in PATH")
endif()

message(STATUS "Found clang: ${CLANG_EXECUTABLE}")

find_program(BPFT_TOOL bpftool)

# Check for BPFTool
if(NOT BPFT_TOOL)
  message(FATAL_ERROR "bpftool is required to generate skeleton headers")
endif()

message(STATUS "Found bpftool: ${BPFT_TOOL}")

message(STATUS "")
# ##############################################################################
