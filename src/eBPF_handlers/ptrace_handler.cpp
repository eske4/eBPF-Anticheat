#include "ptrace_handler.h"
#include <bpf/libbpf.h>
#include <iostream>
#include "../shared.h"
#include "string.h"

int handle_event(void *ctx, void *data, size_t data_sz)
{
    memmove(ctx, data, data_sz);
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
        &this->data,
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

const ptrace_event ptrace_handler::GetData()
{
    return data;
}

ptrace_handler::~ptrace_handler() { DetachAndUnloadAll(); }
