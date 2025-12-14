#pragma once

#define MY_TASK_COMM_LEN 16
#define FILENAME_LEN 4096
#define KMOD_NAME_LEN 64

enum module_event_state { LOADED = 1, UNLOADED = 2 };
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
  char name[KMOD_NAME_LEN];      // module name
  unsigned int taints;           // kernel taints
  enum module_event_state state; // module state
  int pid;                       // PID that loaded the module
  int timestamp_ns;              // event timestamp
};
