#include "kmod_tracker_agent.h"
#include "mem_access_agent.h"
#include <iostream>
#include <signal.h>

bool stop = false;
void siginthandler(int param) {
  (void)param;
  stop = true;
  std::cout << std::endl;
}

int main(int argc, char *argv[]) {
  std::cout << "--- Anti-Cheat Handler Test ---" << std::endl;

  pid_t protected_pid = (argc > 1) ? static_cast<pid_t>(std::stoi(argv[1]))
                                   : static_cast<pid_t>(792);
                                   

  mem_access_agent mem_agent = mem_access_agent(protected_pid);
  kmod_tracker_agent module_agent = kmod_tracker_agent();


  mem_agent.set_block_access(true); //Set to true to make eBPF block access
  int mem_event_hooks[6] = {1, 1, 1, 1, 1, 1}; // default print all event 

  if (argc > 8) {
    mem_agent.set_block_access(std::stoi(argv[2]) == 1); 
    mem_event_hooks[0] = std::stoi(argv[3]); // PTRACE
    mem_event_hooks[1] = std::stoi(argv[4]); // OPEN
    mem_event_hooks[2] = std::stoi(argv[5]); // WRITE
    mem_event_hooks[3] = std::stoi(argv[6]); // READ
    mem_event_hooks[4] = std::stoi(argv[7]); // VM_WRITE
    mem_event_hooks[5] = std::stoi(argv[8]); // VM_READ
  }

  // 1. Load and Attach
  std::cout << "\n========================================================"<< std::endl;
  std::cout << "program protected pid: " << protected_pid << std::endl;
  std::cout << "Check the trace pipe in a new terminal:" << std::endl;
  std::cout << "run \"sudo cat /sys/kernel/tracing/trace_pipe\" or \"make debug\"" << std::endl;
  std::cout << "Press CTRL+C to unload the programs..." << std::endl;

  signal(SIGINT, siginthandler);
  while (!stop) {
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
      if (e2.type < 6 && mem_event_hooks[e2.type] == 1) {
        mem_agent.printEventData(e2);
      }
      //mem_agent.writeEventDataToCSV(e2);
      maybe_mem_agent = mem_agent.get_next_event();
    }

    // Sleep briefly to avoid busy-waiting
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  return 0;
}
