# Output directories
set(BPF_OUT ${CMAKE_BINARY_DIR}/bpfs)
set(SKEL_OUT_DIR ${CMAKE_BINARY_DIR}/skeletons)

# Headers and programs to generate/compile
set(VMLINUX_H ${BPF_OUT}/vmlinux.h)
set(EBPF_PROGRAMS module_tracker.bpf.c mem_access.bpf.c) # Add eBPF programs here

get_target_property(DATATYPES_INCLUDES DataTypes INTERFACE_INCLUDE_DIRECTORIES)

# Fetch header files from interface library
set(DATATYPES_INCLUDE_FLAGS "")
foreach(dir ${DATATYPES_INCLUDES})
  list(APPEND DATATYPES_INCLUDE_FLAGS "-I${dir}")
endforeach()

# Compile eBPF programs and generate skeletons
foreach(src ${EBPF_PROGRAMS})
  get_filename_component(name ${src} NAME_WE)
  set(OUT ${BPF_OUT}/${name}.o)
  set(SKEL_H ${SKEL_OUT_DIR}/${name}.skel.h)

  add_custom_command(
    OUTPUT ${OUT}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${src}
    COMMAND
      ${CLANG_EXECUTABLE} "-target" "bpf" "-O2" "-g"
      "-D__TARGET_ARCH_${BPF_ARCH}" "-I${BPF_OUT}" "${DATATYPES_INCLUDE_FLAGS}"
      "-c" "${CMAKE_CURRENT_SOURCE_DIR}/${src}" "-o" "${OUT}"
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
