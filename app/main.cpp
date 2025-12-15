#include "mem_access_agent.h"
#include "module_tracker_agent.h"
#include <iostream>

int main() {
  std::cout << "--- Anti-Cheat Handler Test ---" << std::endl;

  pid_t protected_pid = 792;

  mem_access_agent mem_agent = mem_access_agent(protected_pid);
  module_tracker_agent module_agent = module_tracker_agent();

  while (true) {
    // Try to get the next event
    auto maybe_module_event = module_agent.get_next_event();
    auto maybe_mem_agent = mem_agent.get_next_event();

    while (maybe_module_event) {
      const module_event &e = *maybe_module_event;
      module_agent.printEventData(e);
      maybe_module_event = module_agent.get_next_event();
    }

    while (maybe_mem_agent) {
      const mem_event &e2 = *maybe_mem_agent;
      mem_agent.printEventData(e2);
      maybe_mem_agent = mem_agent.get_next_event();
    }

    // Sleep briefly to avoid busy-waiting
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  std::string temp;
  std::getline(std::cin, temp);

  return 0;
}
