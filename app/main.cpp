#include "mem_access_agent.h"
#include "module_handler.h"
#include "module_tracker_agent.h"
#include <iostream>

int main() {
  std::cout << "--- Anti-Cheat Handler Test ---" << std::endl;

  pid_t protected_pid = 792;

  mem_access_agent mem_access_agent(protected_pid);
  module_tracker_agent module_agent = module_tracker_agent();

  // 1. Load and Attach
  std::cout << "\n========================================================"
            << std::endl;
  std::cout << "Check the trace pipe in a new terminal:" << std::endl;
  std::cout << "sudo cat /sys/kernel/tracing/trace_pipe" << std::endl;
  std::cout << "Press ENTER to continue and unload the programs..."
            << std::endl;

  std::string temp;
  std::getline(std::cin, temp);

  return 0;
}
