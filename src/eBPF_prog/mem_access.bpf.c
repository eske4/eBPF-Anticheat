#include "data_types.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

volatile const pid_t PROTECTED_PID = 0;

struct
{
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * sizeof(struct mem_event));
} rb SEC(".maps");


SEC("tp/syscalls/sys_enter_ptrace")
int ptrace_entry(struct trace_event_raw_sys_enter *ctx)
{
  pid_t caller = (pid_t)(bpf_get_current_pid_tgid() >> 32);
  pid_t target;
  bpf_core_read(&target, sizeof(target), &ctx->args[1]);

  if (target != PROTECTED_PID || caller == PROTECTED_PID)
    return 0;

  struct mem_event *e =
      bpf_ringbuf_reserve(&rb, sizeof(struct mem_event), 0);
  if (!e)
    return 0;

  e->type = PTRACE;
  e->caller = caller;
  e->target = target;
  bpf_get_current_comm(e->caller_name, sizeof(e->caller_name));

  bpf_printk("ptrace called by %s(pid %i), attaching to process %i",
             e->caller_name, e->caller, e->target);

  bpf_ringbuf_submit(e, 0);

  return 0;
}




int handle_process_vm_rw(pid_t pid, bool is_write)
{
  if (pid != PROTECTED_PID)
    return 0;

  struct mem_event *e = bpf_ringbuf_reserve(&rb, sizeof(struct mem_event), 0);
  if (!e)
    return 0;

  e->type = is_write ? VM_WRITE : VM_READ;
  e->caller = (pid_t)(bpf_get_current_pid_tgid() >> 32);
  e->target = pid;
  bpf_get_current_comm(e->caller_name, sizeof(e->caller_name));

  bpf_printk("process_vm_rw called by %s(pid %i), for process %i",
             e->caller_name, e->caller, e->target);

  bpf_ringbuf_submit(e, 0);

  return 0;
}

SEC("tp/syscalls/sys_enter_process_vm_readv")
int trace_readv(struct trace_event_raw_sys_enter *ctx)
{
    pid_t pid = (pid_t)BPF_CORE_READ(ctx, args[0]); 
    return handle_process_vm_rw(pid, false);
}

SEC("tp/syscalls/sys_enter_process_vm_writev")
int trace_writev(struct trace_event_raw_sys_enter *ctx)
{
    pid_t pid = (pid_t)BPF_CORE_READ(ctx, args[0]); 
    return handle_process_vm_rw(pid, true);
}
