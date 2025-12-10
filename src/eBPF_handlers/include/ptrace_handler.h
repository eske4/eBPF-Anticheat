#pragma once
#include "ptrace.skel.h"
#include <memory>
#include <future>
#include "../../shared.h"

class ptrace_handler {
public:
  ptrace_handler() = default;

  ~ptrace_handler();

  /// @param protected_pid The pid of the game/process to protect
  int LoadAndAttachAll(pid_t protected_pid);
  void DetachAndUnloadAll();
  const struct ptrace_event GetData();

private:
  std::unique_ptr<struct ptrace, decltype(&ptrace__destroy)>
      skel_obj{nullptr, ptrace__destroy};

  std::unique_ptr<struct ring_buffer, decltype(&ring_buffer__free)>
      rb{nullptr, ring_buffer__free};

  std::future<void> loop_thread;
  bool run = true;
  struct ptrace_event data;
};
