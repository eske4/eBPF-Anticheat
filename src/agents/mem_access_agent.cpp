#include "mem_access_agent.h"
#include <iostream>

const char *event_type_to_string(mem_event_type type) {
  switch (type) {
  case PTRACE:
    return "PTRACE";
  case OPEN:
    return "OPEN";
  case VM_WRITE:
    return "VM_WRITE";
  case VM_READ:
    return "VM_READ";
  default:
    return "UNKNOWN_EVENT";
  }
}

auto on_event = [](const mem_event &e) {
  const auto &[type, caller, target, caller_name, filename] = e;

  std::cout << "[BPF EVENT: " << event_type_to_string(type) << "] ";

  switch (type) {
  case PTRACE:
    std::cout << "PTRACE requested by " << caller_name << " (PID " << caller
              << ") to attach to process (PID " << target << ").\n";
    break;

  case VM_WRITE:
    std::cout << "VM_WRITE executed by " << caller_name << " (PID " << caller
              << ") targeting protected process (PID " << target << ").\n";
    break;

  case VM_READ:
    std::cout << "VM_READ executed by " << caller_name << " (PID " << caller
              << ") reading from protected process (PID " << target << ").\n";
    break;

  case OPEN:
    std::cout << "OPEN syscall called by " << caller_name << " (PID " << caller
              << ") for file: " << filename << ".\n";
    break;

  default:
    std::cout << "Unknown syscall type (" << (int)type
              << ") observed. Caller: " << caller_name << " (PID " << caller
              << "). Target PID: " << target << ".\n";
    break;
  }
};

mem_access_agent::mem_access_agent(pid_t protected_pid) : handler(on_event) {
  this->protected_pid = protected_pid;
  handler.LoadAndAttachAll(protected_pid);
}

mem_access_agent::~mem_access_agent() { handler.DetachAndUnloadAll(); }

void mem_access_agent::set_protected_pid(pid_t protected_pid) {
  this->protected_pid = protected_pid;
  handler.DetachAndUnloadAll();
  handler.LoadAndAttachAll(protected_pid);
}

int mem_access_agent::get_pid_id() { return protected_pid; }
