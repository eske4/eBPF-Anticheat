#pragma once

#include <cstdint>

constexpr int my_task_comm_len = 16;
constexpr int filename_len = 64;

enum mem_event_type : uint32_t {
  PTRACE = 0,
  OPEN = 1,
  WRITE = 2,
  READ = 3,
  VM_WRITE = 4,
  VM_READ = 5,
  PROCFS = 6,
  K_TASK_LOOKUP = 7,
  K_VPID_LOOKUP = 8,
};

struct mem_event {
  enum mem_event_type type;
  uint32_t caller;
  uint32_t target;
  char caller_name[my_task_comm_len];
  char filename[filename_len];
};
