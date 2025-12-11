#pragma once
#include "ptrace.skel.h"
#include <memory>
#include <future>
#include "../../shared.h"
#include <functional>

class ptrace_handler {
public:
  /// @param onEvent A function that runs when new data arrives from eBPF programs
  ptrace_handler(std::function<void(ptrace_event)> onEvent);

  ~ptrace_handler();

  /// @param protected_pid The pid of the game/process to protect
  int LoadAndAttachAll(pid_t protected_pid);

  void DetachAndUnloadAll();


private:
  static int ring_buffer_callback(void *ctx, void *data, size_t data_sz);

  std::unique_ptr<struct ptrace, decltype(&ptrace__destroy)>
      skel_obj{nullptr, ptrace__destroy};

  std::unique_ptr<struct ring_buffer, decltype(&ring_buffer__free)>
      rb{nullptr, ring_buffer__free};

  bool run;
  std::future<void> loop_thread;
  std::function<void(ptrace_event)> onEvent;
};
