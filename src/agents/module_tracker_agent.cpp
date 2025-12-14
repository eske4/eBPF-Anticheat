#include "module_tracker_agent.h"
#include "data_types.h"
#include <iostream>

const char *event_type_to_string(module_event_state state) {
  switch (state) {
  case LOADED:
    return "PTRACE";
  case UNLOADED:
    return "OPEN";
  default:
    return "UNKNOWN_EVENT";
  }
}

auto on_event = [](const module_event &e) {
  const auto &[name, taints, state, pid, timestamp_ns] = e;

  std::cout << "[BPF EVENT: " << event_type_to_string(state) << "] ";

  switch (state) {
  case LOADED:
    std::cout << "The module " << name << "\nis loaded: " << state
              << "\ntaints status: " << taints << "\nperformed by pid: " << pid
              << "\nat" << timestamp_ns;
    break;

  case UNLOADED:
    std::cout << "The module " << name << "\nis loaded: " << state
              << "\ntaints status: " << taints << "\nperformed by pid: " << pid
              << "\nat" << timestamp_ns;
    break;

  default:
    std::cout << "Unknown module event \n";
    break;
  }
};

module_tracker_agent::module_tracker_agent() : handler(on_event) {
  handler.LoadAndAttachAll();
}

module_tracker_agent::~module_tracker_agent() { handler.DetachAndUnloadAll(); }
