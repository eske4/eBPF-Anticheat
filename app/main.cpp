#include "module_handler.h"
#include "ptrace_handler.h"
#include "ptrace_agent.h"
#include <iostream>

int main() {
  std::cout << "--- Anti-Cheat Handler Test ---" << std::endl;

  pid_t protected_pid = 37091;

  module_handler handler;
  //ptrace_handler ptrace_handler;
  ptrace_agent ptrace_agent;

  // 1. Load and Attach
  if (handler.LoadAndAttachAll() != 0) {
    std::cerr << "FATAL: Failed to load eBPF programs. Check dmesg/permissions."
              << std::endl;
    return 1;
  }


  std::cout << "\n========================================================"
            << std::endl;
  std::cout << "Check the trace pipe in a new terminal:"
            << std::endl;
  std::cout << "sudo cat /sys/kernel/tracing/trace_pipe"
            << std::endl;
  std::cout << "Press ENTER to continue and unload the programs..."
            << std::endl;

  std::string temp;
  std::getline(std::cin, temp);

  ptrace_agent.print_ptrace();

  return 0;
}