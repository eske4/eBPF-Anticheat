#include "module_handler.h"
#include "data_types.h"
#include "string.h"
#include <bpf/libbpf.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <thread>

int module_handler::ring_buffer_callback(void *ctx, void *data,
                                         size_t data_sz) {
  if (data_sz != sizeof(mem_event)) {
    std::cerr << "Size mitch match in event";
    return 1; // Return non-zero to indicate a processing error
  }

  auto *handler = static_cast<module_handler *>(ctx);

  module_event e;
  std::memcpy(&e, data, sizeof(e));
  handler->on_event(e);

  return 0;
}

int module_handler::LoadAndAttachAll() {
  if (!on_event) {
    std::cerr << "No on_event callback set\n";
    return -1;
  }

  int err = 0;

  skel_obj.reset(module_tracker__open());
  if (!skel_obj) {
    std::cerr << "ERROR: Failed to open BPF skeleton object." << std::endl;
    return -1;
  }

  err = module_tracker__load(skel_obj.get());
  if (err) {
    std::cerr << "ERROR: Failed to load BPF programs into kernel: " << err
              << std::endl;
    skel_obj.reset();
    return err;
  }

  rb.reset(ring_buffer__new(bpf_map__fd(skel_obj->maps.rb),
                            module_handler::ring_buffer_callback, this,
                            nullptr));

  if (!rb) {
    std::cerr << "ERROR: Failed to create ring buffer\n";
    skel_obj.reset();
    return -1;
  }

  err = module_tracker__attach(skel_obj.get());
  if (err) {
    std::cerr << "ERROR: Failed to attach BPF programs to hook points: " << err
              << std::endl;
    rb.reset();
    skel_obj.reset();
    return err;
  }

  loop_thread = std::jthread([this](std::stop_token st) {
    while (!st.stop_requested()) {
      int ret = ring_buffer__poll(rb.get(), 100);

      if (ret < 0) {
        // Check if the cause is intereupted system call which is not fatal and
        // should keep pooling
        if (ret == -EINTR)
          continue;
        std::cerr << "ring_buffer__poll error: " << ret << "\n";
        break;
      }
    }
  });

  return 0;
}

module_handler::module_handler(std::function<void(module_event)> cb)
    : on_event(std::move(cb)) {}

void module_handler::DetachAndUnloadAll() {

  if (loop_thread.joinable()) {
    loop_thread.request_stop();
    // Wait for the thread to terminate before cleanup
    loop_thread.join();
  }

  rb.reset();
  skel_obj.reset();

  std::cout << "module_tracker eBPF program detached and unloaded.\n";
}

module_handler::~module_handler() { DetachAndUnloadAll(); }
