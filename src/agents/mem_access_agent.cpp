#include "mem_access_agent.h"
#include "mem_data.h"
#include <iostream>

std::string_view event_type_to_string(mem_event_type type);

mem_access_agent::mem_access_agent(pid_t protected_pid)
    : handler([this](const mem_event &e) { on_event_cb(e); }) {
  this->protected_pid = protected_pid;
  handler.LoadAndAttachAll(protected_pid);
}

mem_access_agent::~mem_access_agent() { handler.DetachAndUnloadAll(); }

void mem_access_agent::on_event_cb(const mem_event &e) {
  std::lock_guard<std::mutex> lock(queue_mutex);
  event_queue.push(e);
}

std::optional<mem_event> mem_access_agent::get_next_event() {
  std::lock_guard<std::mutex> lock(queue_mutex);
  if (event_queue.empty())
    return std::nullopt;
  mem_event e = event_queue.front();
  event_queue.pop();
  return e;
}

void mem_access_agent::set_protected_pid(pid_t protected_pid) {
  this->protected_pid = protected_pid;
  handler.DetachAndUnloadAll();
  handler.LoadAndAttachAll(protected_pid);
}

int mem_access_agent::get_pid_id() { return protected_pid; }

void mem_access_agent::printEventData(const mem_event &e) {

  std::cout << "===== Memory Event =====\n";
  std::cout << "Caller name       : " << e.caller_name << "\n";
  std::cout << "PID        : " << e.caller << "\n";
  std::cout << "Filename      : " << e.filename << "\n";
  std::cout << "Target     : " << e.target;
  std::cout << "=======================\n";
}

std::string_view event_type_to_string(mem_event_type type) {
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
