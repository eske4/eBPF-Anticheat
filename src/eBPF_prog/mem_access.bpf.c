#include "data_types.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

volatile const pid_t PROTECTED_PID = 0;

struct
{
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(key_size, 1 * sizeof(int));
  __uint(value_size, 16 * sizeof(char));
  __uint(max_entries, 1);
} protected_pid_s_map SEC(".maps");

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



SEC("lsm/file_open")
int BPF_PROG(check_proc_access, struct file *file)
{
  pid_t current_pid = bpf_get_current_pid_tgid() >> 32;
  if (current_pid == PROTECTED_PID)
    return 0;

  struct mem_event *e = bpf_ringbuf_reserve(&rb, sizeof(struct mem_event), 0);
  if (!e)
  {
    return 0;
  }

  if (bpf_path_d_path(&file->f_path, e->filename, sizeof(e->filename)) < 0) // should return resolved (full) path ??
  {
    goto cleanup;
  }

  if (e->filename[0] != '/' || e->filename[1] != 'p' ||
      e->filename[2] != 'r' || e->filename[3] != 'o' ||
      e->filename[4] != 'c' || e->filename[5] != '/')
  {
    goto cleanup;
  }

  char *ptr = &e->filename[6];
  char *ptr_protected;

  int key = 0;
  ptr_protected = bpf_map_lookup_elem(&protected_pid_s_map, &key);
  if (!ptr_protected)
  {
    goto cleanup;
  }

  int i = 0;
  if (ptr[i] <= '0' || ptr[i] >= '9')
  {
    goto cleanup; // not a pid
  }

  while (ptr[i] >= '0' && ptr[i] <= '9' && ptr_protected[i] >= '0' && ptr_protected[i] <= '9' && i < 15)
  {
    if (ptr[i] != ptr_protected[i])
    {
      goto cleanup; // no match
    }
    i++;
  }

  if (ptr_protected[i] != '\0' || (ptr[i] >= '0' && ptr[i] <= '9'))
  {
    goto cleanup; // only partial match
  }

  e->caller = current_pid;
  bpf_get_current_comm(e->caller_name, sizeof(e->caller_name));
  e->type = OPEN;
  e->target = PROTECTED_PID;

  bpf_printk("procfs file opened: %s by %s\n", e->filename, e->caller_name);
  bpf_ringbuf_submit(e, 0);
  return 0;

cleanup:
  bpf_ringbuf_discard(e, 0);
  return 0;
}