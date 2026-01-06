/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>

#define KMOD_NAME_LEN 64

enum module_event_state { LOADED = 1, UNLOADED = 2 };

struct module_event {
  char name[KMOD_NAME_LEN];      // module name
  unsigned int taints;           // kernel taints
  enum module_event_state state; // module state
  pid_t pid;                     // PID that loaded the module
  u64 timestamp_ns;              // event timestamp
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * sizeof(struct module_event));
} rb SEC(".maps");

// Use BPF-defined types directly

const pid_t pid_filter = 0;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int getModuleInfo(struct trace_event_raw_module_load *ctx,
                  enum module_event_state state); // Helper function

int handle_module_load(struct trace_event_raw_module_load *ctx);
int handle_module_unload(struct trace_event_raw_module_load *ctx);

SEC("tp/module/module_load")
int handle_module_load(struct trace_event_raw_module_load *ctx) {
  bpf_printk("loaded: ");
  return getModuleInfo(ctx, LOADED);
}

SEC("tp/module/module_free")
int handle_module_unload(struct trace_event_raw_module_load *ctx) {
  bpf_printk("unloaded: ");
  return getModuleInfo(ctx, UNLOADED);
}

int getModuleInfo(struct trace_event_raw_module_load *ctx,
                  enum module_event_state state) {
  struct module_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e)
    return 0;

  // Read module name directly into struct
  u32 name_offset;
  bpf_core_read(&name_offset, sizeof(name_offset), &ctx->__data_loc_name);
  bpf_probe_read_kernel_str(e->name, sizeof(e->name),
                            (void *)ctx + (name_offset & 0xFFFF));

  // Copy scalar fields
  e->taints = ctx->taints;
  e->state = state;
  e->pid = bpf_get_current_pid_tgid() >> 32;
  e->timestamp_ns = bpf_ktime_get_ns();

  bpf_ringbuf_submit(e, 0);
  return 0;
}

SEC("lsm/kernel_read_file")
int BPF_PROG(block_all_modules, struct file *file, enum kernel_read_file_id id, bool contents)
{
    // READING_MODULE is the ID for kernel modules
    if (id == READING_MODULE) {
        bpf_printk("Blocking module load via kernel_read_file");
        return -EPERM; 
    }
    return 0;
}
