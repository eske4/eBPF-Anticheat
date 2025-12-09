#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../shared.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

volatile const pid_t PROTECTED_PID = 0;

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * sizeof(struct ptrace_event));
} rb SEC(".maps");

SEC("tp/syscalls/sys_enter_ptrace")
int ptrace_entry(struct trace_event_raw_sys_enter *ctx)
{
    pid_t caller = (pid_t)(bpf_get_current_pid_tgid() >> 32);
    pid_t target = (pid_t)ctx->args[1];

    if (target != PROTECTED_PID || caller == PROTECTED_PID)
        return 0;

    struct ptrace_event *e = bpf_ringbuf_reserve(&rb, sizeof(struct ptrace_event), 0);
    if (!e) return 0;

    e->caller = caller;
    e->target = target;
    bpf_get_current_comm(e->caller_name, sizeof(e->caller_name));

    bpf_printk("ptrace called by %s(pid %i), attaching to process %i", e->caller_name, e->caller, e->target);

    bpf_ringbuf_submit(e, 0);

    return 0;
}
