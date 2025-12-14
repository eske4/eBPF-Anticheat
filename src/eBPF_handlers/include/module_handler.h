#pragma once
#include "data_types.h"
#include "module_tracker.skel.h"
#include <functional>
#include <memory>
#include <thread>

class module_handler {
public:
  /// @param on_event A function that runs when new data arrives from eBPF
  /// programs
  explicit module_handler(std::function<void(module_event)> on_event);
  ~module_handler();

  /// @param protected_pid The pid of the game/process to protect
  int LoadAndAttachAll();
  void DetachAndUnloadAll();

private:
  static int ring_buffer_callback(void *ctx, void *data, size_t data_sz);

  std::unique_ptr<struct module_tracker, decltype(&module_tracker__destroy)>
      skel_obj{nullptr, module_tracker__destroy};

  std::unique_ptr<struct ring_buffer, decltype(&ring_buffer__free)> rb{
      nullptr, ring_buffer__free};

  std::jthread loop_thread;
  std::function<void(module_event)> on_event;
};
