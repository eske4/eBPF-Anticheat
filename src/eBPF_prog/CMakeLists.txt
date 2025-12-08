# Output directories
set(BPF_OUT ${CMAKE_BINARY_DIR}/bpfs)
set(SKEL_OUT_DIR ${CMAKE_BINARY_DIR}/skeletons)

# Create output directories
file(MAKE_DIRECTORY ${BPF_OUT})
file(MAKE_DIRECTORY ${SKEL_OUT_DIR})

# vmlinux.h
set(VMLINUX_H ${BPF_OUT}/vmlinux.h)
set(EBPF_PROGRAMS module_tracker.bpf.c) # Add eBPF programs here

add_custom_command(
  OUTPUT ${VMLINUX_H}
  COMMAND bpftool btf dump file /sys/kernel/btf/vmlinux format c > ${VMLINUX_H}
  WORKING_DIRECTORY ${BPF_OUT}
  COMMENT "Generating vmlinux.h")

add_custom_target(vmlinux_btf ALL DEPENDS ${VMLINUX_H})

# eBPF programs
foreach(src ${EBPF_PROGRAMS})
  get_filename_component(name ${src} NAME_WE)
  set(OUT ${BPF_OUT}/${name}.o)
  set(SKEL_H ${SKEL_OUT_DIR}/${name}.skel.h)

  add_custom_command(
    OUTPUT ${OUT}
    COMMAND
      ${CLANG_EXECUTABLE} "-target" "bpf" "-O2" "-g"
      "-D__TARGET_ARCH_${BPF_ARCH}" "-I${BPF_OUT}" "-c"
      "${CMAKE_CURRENT_SOURCE_DIR}/${src}" "-o" "${OUT}"
    DEPENDS ${src} vmlinux_btf
    COMMENT "Compiling ${name}.bpf.o")
  # Generate skeleton header
  add_custom_command(
    OUTPUT ${SKEL_H}
    COMMAND bpftool gen skeleton "${OUT}" > "${SKEL_H}"
    DEPENDS ${OUT}
    COMMENT "Generating skeleton header ${name}.skel.h")

  # Targets
  add_custom_target(${name}_bpf ALL DEPENDS ${OUT} ${SKEL_H})
endforeach()
