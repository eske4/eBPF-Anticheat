set(AGENTS_SOURCES module_tracker_agent.cpp mem_access_agent.cpp)

add_library(Agents ${AGENTS_SOURCES})

target_include_directories(Agents PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(Agents eBPF_Handlers)

