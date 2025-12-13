#include "mem_access_handler.h"
#include "data_types.h"
#include "string.h"
#include <bpf/libbpf.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <thread>

int mem_access_handler::ring_buffer_callback(void *ctx, void *data,
                                             size_t data_sz) {
  if (data_sz != sizeof(mem_event)) {
    std::cerr << "Size mitch match in event";
    return 1; // Return non-zero to indicate a processing error
  }

  auto *handler = static_cast<mem_access_handler *>(ctx);

  mem_event e;
  std::memcpy(&e, data, sizeof(e));
  handler->on_event(e);

  return 0;
}

int mem_access_handler::LoadAndAttachAll(pid_t protected_pid) {
  if (!on_event) {
    std::cerr << "No on_event callback set\n";
    return -1;
  }

  int err = 0;

  skel_obj.reset(mem_access__open());
  if (!skel_obj) {
    std::cerr << "ERROR: Failed to open BPF skeleton object." << std::endl;
    return -1;
  }

  skel_obj.get()->rodata->PROTECTED_PID = protected_pid;

  err = mem_access__load(skel_obj.get());
  if (err) {
    std::cerr << "ERROR: Failed to load BPF programs into kernel: " << err
              << std::endl;
    skel_obj.reset();
    return err;
  }

  rb.reset(ring_buffer__new(bpf_map__fd(skel_obj->maps.rb),
                            mem_access_handler::ring_buffer_callback, this,
                            nullptr));

  if (!rb) {
    std::cerr << "ERROR: Failed to create ring buffer\n";
    skel_obj.reset();
    return -1;
  }

  err = mem_access__attach(skel_obj.get());
  if (err) {
    std::cerr << "ERROR: Failed to attach BPF programs to hook points: " << err
              << std::endl;
    rb.reset();
    skel_obj.reset();
    return err;
  }

  // copy the protected_pid as a string to ebpf map
  std::string protected_pid_s = std::to_string(protected_pid);
  char data[16] = {};
  size_t copy_len = std::min(protected_pid_s.length() + 1, sizeof(data));
  std::memcpy(data, protected_pid_s.c_str(), copy_len);
  int key = 0;
  bpf_map__update_elem(skel_obj.get()->maps.protected_pid_s_map, &key, sizeof(int), data, sizeof(data), 0);
  

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

mem_access_handler::mem_access_handler(std::function<void(mem_event)> cb)
    : on_event(std::move(cb)) {}

void mem_access_handler::DetachAndUnloadAll() {

  if (loop_thread.joinable()) {
    loop_thread.request_stop();
    // Wait for the thread to terminate before cleanup
    loop_thread.join();
  }

  rb.reset();
  skel_obj.reset();

  std::cout << "mem_access eBPF program detached and unloaded.\n";
}

mem_access_handler::~mem_access_handler() { DetachAndUnloadAll(); }
