#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MY_TASK_COMM_LEN 16
#define MY_FILENAME_LEN 64
#define PROC_SUPER_MAGIC 0x9fa0


const pid_t PROTECTED_PID;

enum mem_event_type {
  PTRACE = 0,
  OPEN = 1,
  WRITE = 2,
  READ = 3,
  VM_WRITE = 4,
  VM_READ = 5,
  PROCFS = 6,
};

struct mem_event {
  enum mem_event_type type;
  int caller;
  int target;
  char caller_name[MY_TASK_COMM_LEN];
  char filename[MY_FILENAME_LEN];
};

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
int BPF_PROG(restrict_proc_access, struct file *file)
{
  pid_t caller_pid = bpf_get_current_pid_tgid() >> 32;
  if (caller_pid == PROTECTED_PID)
    return 0;

  unsigned long magic = BPF_CORE_READ(file, f_inode, i_sb, s_magic);
  if (magic != PROC_SUPER_MAGIC)
    return 0; // return if not part of procfs

  // file->f_path.dentry->d_name.name
  char *name = (char*)BPF_CORE_READ(file, f_path.dentry, d_name.name);

  bool is_restricted_file_name = (bpf_strcmp(name, "maps") == 0 || 
                                  bpf_strcmp(name, "smaps") == 0 || 
                                  bpf_strcmp(name, "mem") == 0);
  if (is_restricted_file_name)
  {
    char *parent_name = (char*)BPF_CORE_READ(file, f_path.dentry, d_parent, d_name.name);
    char protected_pid_s[16];
    BPF_SNPRINTF(protected_pid_s, sizeof(protected_pid_s), "%d", PROTECTED_PID);

    bool is_parent_protected_pid = bpf_strcmp(protected_pid_s, parent_name) == 0;

    if (is_parent_protected_pid) {
      struct mem_event *e = bpf_ringbuf_reserve(&rb, sizeof(struct mem_event), 0);
      if (!e)
        return -EPERM;

      e->type = PROCFS;
      e->caller = caller_pid;
      e->target = PROTECTED_PID;
      bpf_core_read_str(e->filename, sizeof(file->f_path.dentry->d_name.len), file->f_path.dentry->d_name.name);
      bpf_get_current_comm(e->caller_name, sizeof(e->caller_name));

      bpf_printk("open called by %s(pid %i), for /proc/%i",
                e->caller_name, e->caller, e->target);

      bpf_ringbuf_submit(e, 0);
      return -EPERM;
    }
    return 0;
  }
  
  return 0;
}

SEC("kprobe/find_vpid")
int BPF_KPROBE(kprobe_find_vpid, int nr)
{
  pid_t looked_up_pid = (pid_t)nr;

  if (looked_up_pid != PROTECTED_PID) {
    return 0;
  }

  char name[MY_TASK_COMM_LEN];
  bpf_get_current_comm(name, sizeof(name));
  bpf_printk("vpid lookup by %s, arg: %i", name, nr);
  return 0;
}

SEC("kretprobe/pid_task")
int BPF_KRETPROBE(kprobe_pid_task_exit, struct task_struct *return_val)
{
  pid_t looked_up_pid = BPF_CORE_READ(return_val, pid);
  
  if (looked_up_pid != PROTECTED_PID) {
    return 0;
  }
  
  char name[MY_TASK_COMM_LEN];
  bpf_get_current_comm(name, sizeof(name));
  bpf_printk("task lookup by %s, arg: %i", name, looked_up_pid);
  return 0;
}