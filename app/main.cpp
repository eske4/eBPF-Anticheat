#include "module_handler.h"
#include <iostream>
#include <string>
#include <unistd.h> // For the sleep function

int main() {
  std::cout << "--- Anti-Cheat Handler Test ---" << std::endl;

  // The module_handler object, which will manage the BPF program's life cycle.
  // The destructor will automatically call DetachAndUnloadAll() upon exit.
  module_handler handler;

  // 1. Load and Attach
  std::cout << "\nAttempting to load BPF programs..." << std::endl;
  if (handler.LoadAndAttachAll() != 0) {
    std::cerr << "FATAL: Failed to load eBPF programs. Check dmesg/permissions."
              << std::endl;
    // The handler's destructor will still be called when main returns,
    // attempting cleanup.
    return 1;
  }

  // 2. Pause Execution for Manual Verification
  std::cout << "\n========================================================"
            << std::endl;
  std::cout << "SUCCESS: BPF programs are running in the kernel." << std::endl;
  std::cout << "ACTION REQUIRED: Please check the trace pipe in a new terminal:"
            << std::endl;
  std::cout << "  $ sudo cat /sys/kernel/tracing/trace_pipe" << std::endl;
  std::cout << "========================================================"
            << std::endl;
  std::cout << "Press ENTER to continue and unload the programs..."
            << std::endl;

  std::string temp;
  std::getline(std::cin, temp);

  // 3. Detach and Unload (Explicit or Implicit)
  // We call it explicitly here for demonstration, but the destructor (called
  // when 'handler' goes out of scope) would handle this automatically if you
  // didn't call it here.
  std::cout << "\nExplicitly calling DetachAndUnloadAll()..." << std::endl;
  handler.DetachAndUnloadAll();

  std::cout
      << "\nTest complete. BPF programs should no longer be generating output."
      << std::endl;

  // When main returns, the 'handler' object is destroyed, which is the final
  // safety net.
  return 0;
}
