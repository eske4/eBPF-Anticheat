/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define KMOD_NAME_LEN 64

// Use BPF-defined types directly
typedef __u32 u32;
typedef int pid_t;

const pid_t pid_filter = 0;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int getModuleInfo(struct trace_event_raw_module_load *ctx); // Helper function

int handle_module_load(struct trace_event_raw_module_load *ctx);
int handle_module_unload(struct trace_event_raw_module_load *ctx);

SEC("tp/module/module_load")
int handle_module_load(struct trace_event_raw_module_load *ctx) {
  bpf_printk("loaded: ");
  return getModuleInfo(ctx);
}

int getModuleInfo(struct trace_event_raw_module_load *ctx) {
  pid_t pid = bpf_get_current_pid_tgid() >> 32;

  // 1. Storage for the offset/pointer value (u32/u64 depending on arch)
  u32 name_offset;

  // 2. Storage for the module name string
  char module_name[KMOD_NAME_LEN] = {};

  // 3. Use BPF_CORE_READ to safely extract the value of the __data_loc_name
  // field. This field contains the offset (or pointer address) to the actual
  // string.
  bpf_core_read(&name_offset, sizeof(name_offset), &ctx->__data_loc_name);

  // 4. Calculate the base address of the string data.
  // The string data itself starts at 'ctx' + the offset.
  // The 'name_offset' value needs to be correctly masked and shifted
  // depending on your kernel, but often, the tracepoint structure is designed
  // to be read directly using the structure base.

  // Try the simplest, most common interpretation for tracepoints:
  // The actual string data is located at the address held by name_offset.

  // We will assume the __data_loc_name field *itself* holds the address/offset
  // to the string data, and the tracepoint context is the base.
  // The simplest working solution often involves pointer arithmetic on the base
  // context:

  void *name_data_ptr = (void *)ctx + (name_offset & 0xFFFF);
  // We mask to 16 bits (0xFFFF) because the lower bits often store the size.

  // 5. Read the string from the calculated address.
  bpf_probe_read_kernel_str(module_name, sizeof(module_name), name_data_ptr);

  bpf_printk("Kernel module %s, by PID %d\n", module_name, pid);
  return 0;
}
