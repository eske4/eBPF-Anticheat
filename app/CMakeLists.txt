add_executable(${PROJECT_NAME} main.cpp)

# Include dirs from pkg-config
target_include_directories(${PROJECT_NAME} PRIVATE ${LIBBPF_INCLUDE_DIRS})

# Link libraries from pkg-config (usually just bpf, elf, z)
target_link_libraries(${PROJECT_NAME} PRIVATE eBPF_Handlers Agents ${LIBBPF_LIBRARIES})

# Optional: output path
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/app)
