#include "module_tracker_agent.h"
#include "data_types.h"
#include <iostream>

module_tracker_agent::module_tracker_agent()
    : handler([this](module_event e) { on_event_cb(e); }) {
  handler.LoadAndAttachAll();
}

module_tracker_agent::~module_tracker_agent() { handler.DetachAndUnloadAll(); }

std::optional<module_event> module_tracker_agent::get_next_event() {
  std::lock_guard<std::mutex> lock(queue_mutex);
  if (event_queue.empty())
    return std::nullopt;
  module_event e = event_queue.front();
  event_queue.pop();
  return e;
}

void module_tracker_agent::on_event_cb(module_event &e) {
  std::lock_guard<std::mutex> lock(queue_mutex);
  event_queue.push(e);
}

void module_tracker_agent::printEventData(const module_event &e) {
  // Convert state enum to string
  const char *state_str = "";
  switch (e.state) {
  case LOADED:
    state_str = "LOADED";
    break;
  case UNLOADED:
    state_str = "UNLOADED";
    break;
  default:
    state_str = "UNKNOWN";
    break;
  }

  std::cout << "===== Module Event =====\n";
  std::cout << "Name       : " << e.name << "\n";
  std::cout << "PID        : " << e.pid << "\n";
  std::cout << "State      : " << state_str << "\n";
  std::cout << "Taints     : 0x" << std::hex << e.taints << std::dec << "\n";
  std::cout << "Timestamp  : " << e.timestamp_ns << " ns\n";
  std::cout << "=======================\n";
}
