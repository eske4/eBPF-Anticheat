add_executable(${PROJECT_NAME} main.cpp)
target_link_libraries(${PROJECT_NAME} eBPF_Handlers ${LIBBPF_INCLUDE_DIRS})

target_link_libraries(${PROJECT_NAME} ${LIBBPF_LIBRARIES})

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/app)
