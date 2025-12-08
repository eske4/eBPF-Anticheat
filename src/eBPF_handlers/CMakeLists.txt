set(eBPF_HANDLER_SOURCES module_handler.cpp)

add_library(eBPF_Handlers ${eBPF_HANDLER_SOURCES})

target_include_directories(
  eBPF_Handlers
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
  PUBLIC ${CMAKE_BINARY_DIR}/skeletons)
