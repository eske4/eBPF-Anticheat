#include "ptrace_handler.h"
#include <bpf/libbpf.h>
#include <iostream>
#include "../shared.h"

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct ptrace_event *e = static_cast<ptrace_event*>(data);
    std::cout << "ptrace called by " << e->caller_name
              << " (pid " << e->caller
              << "), attaching to proc " << e->target
              << std::endl;
    return 0;
}

int ptrace_handler::LoadAndAttachAll(pid_t protected_pid)
{
    int err = 0;

    skel_obj.reset(ptrace__open());
    if (!skel_obj)
    {
        std::cerr << "ERROR: Failed to open BPF skeleton object." << std::endl;
        return -1;
    }

    skel_obj.get()->rodata->PROTECTED_PID = protected_pid;

    err = ptrace__load(skel_obj.get());
    if (err)
    {
        std::cerr << "ERROR: Failed to load BPF programs into kernel: " << err
                  << std::endl;
        skel_obj.reset();
        return err;
    }

    auto buf = ring_buffer__new(
        bpf_map__fd(skel_obj.get()->maps.rb),
        handle_event,
        nullptr,
        nullptr);
    rb.reset(buf);

    err = ptrace__attach(skel_obj.get());
    if (err)
    {
        std::cerr << "ERROR: Failed to attach BPF programs to hook points: " << err
                  << std::endl;
        skel_obj.reset();
        return err;
    }

    run = true;
    loop_thread = std::async([this]()
                             {
    while (this->run) {
        ring_buffer__poll(this->rb.get(), 100);
    } });

    return 0;
}

void ptrace_handler::DetachAndUnloadAll()
{
    skel_obj.reset();
    run = false;
    loop_thread.wait();
    std::cout << "ptrace eBPF program detached and unloaded." << std::endl;
}

ptrace_handler::~ptrace_handler() { DetachAndUnloadAll(); }
