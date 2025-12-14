#pragma once
#include "mem_access.skel.h"
#include "mem_data.h"
#include <functional>
#include <thread>

class mem_access_handler {
public:
  /// @param on_event A function that runs when new data arrives from eBPF
  /// programs
  explicit mem_access_handler(std::function<void(mem_event)> on_event);
  ~mem_access_handler();

  /// @param protected_pid The pid of the game/process to protect
  int LoadAndAttachAll(pid_t protected_pid);
  void DetachAndUnloadAll();

private:
  static int ring_buffer_callback(void *ctx, void *data, size_t data_sz);

  std::unique_ptr<struct mem_access, decltype(&mem_access__destroy)> skel_obj{
      nullptr, mem_access__destroy};

  std::unique_ptr<struct ring_buffer, decltype(&ring_buffer__free)> rb{
      nullptr, ring_buffer__free};

  std::jthread loop_thread;
  std::function<void(mem_event)> on_event;
};
