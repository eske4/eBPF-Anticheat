# TyrSecure — eBPF Anti-Cheat

**TyrSecure** is a prototype anti-cheat system built using **eBPF**, designed to demonstrate kernel-level monitoring and enforcement capabilities.

This project was developed as part of a **Computer Science Master’s Specialization Project** (9th semester, first half of specialization).

---

## Project Goals

- Explore kernel-level observability using eBPF
- Detect suspicious behavior in games
- Serve as a research and educational prototype (not production-ready)

---

## Installation & Setup

### System Requirements

Tested primarily on **Linux (Arch)**. Other modern Linux distributions with recent kernels should also work.

| Component | Requirement |
|----------|-------------|
| **Compiler** | Clang ≥ 21.1.6 |
| **Build Tools** | CMake ≥ 3.25.1 |
| | GNU Make ≥ 4.4.1 |
| **BPF Tools** | bpftool ≥ 7.7.0 |
| **Libraries** | libbpf ≥ 1.7 |
| | pkg-config ≥ 2.5.1 |
| **Kernel** | Linux kernel with eBPF support (recommended: 5.x+) |

> **Note:**  
> - A C23 / C++23-capable toolchain is required  
> - Root privileges are required to load and attach eBPF programs

---

## Building from Source

```sh
git clone https://github.com/eske4/eBPF-Anticheat.git
cd eBPF-Anticheat
make build
```

This builds both the eBPF programs and the userspace controller.

---

## Usage

### Running the Application

Attach the anti-cheat to a target process by providing its PID:

```sh
sudo ./eBPFA <target_pid>
```

Alternatively, use the default run target:

```sh
make run
```

The `make run` target attaches to a predefined PID (default: `792`).
You can modify this value in the `Makefile`.
