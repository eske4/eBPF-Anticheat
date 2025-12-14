#pragma once

#include <cstdint>
#define MY_TASK_COMM_LEN 16
#define FILENAME_LEN 4096
#define KMOD_NAME_LEN 64

enum module_event_state : uint32_t { LOADED = 1, UNLOADED = 2 };
enum mem_event_type {
  PTRACE = 0,
  OPEN = 1,
  WRITE = 2,
  READ = 3,
  VM_WRITE = 4,
  VM_READ = 5,
};

struct mem_event {
  enum mem_event_type type;
  int caller;
  int target;
  char caller_name[MY_TASK_COMM_LEN];
  char filename[FILENAME_LEN];
};

struct module_event {
  char name[64];            // 64 bytes
  uint32_t taints;          // 4 bytes
  module_event_state state; // 4 bytes
  int32_t pid;              // 4 bytes
  uint64_t timestamp_ns;    // 8 bytes
};
