#pragma once

#include <cstdint>

constexpr int kmod_name_len = 64;

enum module_event_state : uint32_t { LOADED = 1, UNLOADED = 2 };

struct module_event {
  char name[kmod_name_len]; // 64 bytes
  uint32_t taints;          // 4 bytes
  module_event_state state; // 4 bytes
  int32_t pid;              // 4 bytes
  uint64_t timestamp_ns;    // 8 bytes
};
