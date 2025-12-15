#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MY_TASK_COMM_LEN 16
#define MY_FILENAME_LEN 64
#define PID_S_MAX_LEN 16

volatile const pid_t PROTECTED_PID = 0;

enum mem_event_type {
  PTRACE = 0,
  OPEN = 1,
  WRITE = 2,
  READ = 3,
  VM_WRITE = 4,
  VM_READ = 5,
};

struct mem_event {
  enum mem_event_type type;
  int caller;
  int target;
  char caller_name[MY_TASK_COMM_LEN];
  char filename[MY_FILENAME_LEN];
};

struct
{
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(key_size, 1 * sizeof(int));
  __uint(value_size, PID_S_MAX_LEN * sizeof(char));
  __uint(max_entries, 1);
} protected_pid_s_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * sizeof(struct mem_event));
} rb SEC(".maps");

SEC("tp/syscalls/sys_enter_ptrace")
int ptrace_entry(struct trace_event_raw_sys_enter *ctx) {
  pid_t caller = (pid_t)(bpf_get_current_pid_tgid() >> 32);
  pid_t target;
  bpf_core_read(&target, sizeof(target), &ctx->args[1]);

  if (target != PROTECTED_PID || caller == PROTECTED_PID)
    return 0;

  struct mem_event *e = bpf_ringbuf_reserve(&rb, sizeof(struct mem_event), 0);
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
    
    char buf[64];
    
    // get full resolved path
    if (bpf_path_d_path(&file->f_path, buf, sizeof(buf)) < 0)
    {
      return 0;
    }
    

  char *filename_ptr = buf;

  if (bpf_strncmp(filename_ptr, 6, "/proc/"))
  {
    return 0; // not in /proc/
  }
  filename_ptr += 6;

  char *ptr_protected;
  char protected_pid_s[PID_S_MAX_LEN] = {0};

  int key = 0;
  ptr_protected = bpf_map_lookup_elem(&protected_pid_s_map, &key);
  if (!ptr_protected)
  {
    return 0;
  }
  if (bpf_probe_read_kernel(protected_pid_s, PID_S_MAX_LEN, ptr_protected) < 0)
  {
    return 0;
  }

  // This next section is stupid but bpf_strncmp can only be used
  // with a static read-only string as 3rd parameter.
  // Therefore I temporarily insert a '\0' while using bpf_strcmp to
  // get the same functionality as bpf_strncmp

  int len = bpf_strnlen(protected_pid_s, PID_S_MAX_LEN);
  if (len <= 0 || len > PID_S_MAX_LEN)
  {
    return 0; // should never happen, but we need to check because ebpf verifier
  }
  if (filename_ptr[len] != '/')
  {
    return 0; // not same len
  }
  char temp = filename_ptr[len];
  filename_ptr[len] = '\0';

  if (bpf_strcmp(protected_pid_s, filename_ptr))
  {
    return 0; // no pid match
  }
  filename_ptr[len] = temp;
  filename_ptr += len;

  // at this point, we know that the file is somewhere in the dir /proc/pid
  // we should only block access to "/mem" and "/maps" and "/smaps" (maybe more, idk yet)
  if (!bpf_strncmp(filename_ptr, 4, "/mem") ||
      !bpf_strncmp(filename_ptr, 5, "/maps") ||
      !bpf_strncmp(filename_ptr, 6, "/smaps"))
  {
    struct mem_event *e = bpf_ringbuf_reserve(&rb, sizeof(struct mem_event), 0);
    if (!e)
    {
      return 0;
    }
    bpf_core_read_str(e->filename, sizeof(buf), buf);
    e->caller = current_pid;
    bpf_get_current_comm(e->caller_name, sizeof(e->caller_name));
    e->type = OPEN;
    e->target = PROTECTED_PID;

    bpf_printk("procfs file opened: %s by %s\n", e->filename, e->caller_name);
    bpf_ringbuf_submit(e, 0);
    return -EPERM;
  }

  return 0;
}
