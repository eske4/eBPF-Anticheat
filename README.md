# eBPFA — eBPF Anti-Cheat

**eBPFA** is a prototype anti-cheat system built using **eBPF**, designed to demonstrate kernel-level monitoring and enforcement capabilities.

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


## Test setup
testing of eBPF program is done, using the open source game *AssaultCube*, and the cheating tools *ac_rhack* and *scanmem* (see next section for cheating methods).

### Game installation guide:
1. Download version v1.2.0.2 of *AssaultCube* from "https://github.com/assaultcube/AC/tags" (that is the version *ac_rhack* work with)
2. Extract files and from root run `./assaultcube.sh` for instalation guide 

### test steps
1. start *AssaultCube*
2. run `make build`if not done yet
3. run `make test` -- if attackcube is running the eBPF program will attach its pid, else default pid 792
    - can also also diable eBPF blocking access and what events it print in terminal by using parameter `TEST_SET="1 1 1 1 1 1 1 1" make test`. The first variable is if block or not (1=block) and the rest are what event to print using, in same order as defined in *src/common/include/data_types.h* (1=print)
    - can also enable logging of event to .csv file -- have to be uncomment from main.cpp

> [!NOTE]  
> - in makefile test runs `@sudo $(BUILD_DIR)/app/eBPFA $$(pidof linux_64_client native_client)
> - This could lead to error if there is another excutable then assaultcube whit this name 

## Cheat methods
### Debugging utility *Scanmem*
instalation using yay: `yay -S scanmem` 
- Scanmem also have a GUI called *Gameconqueror*, can be installed using yay with command: `yay -S gameconqueror`

**process** of memory manipulation using scanmem:
1. start *AssaultCube* 
2. run `ps -aux | grep assaultcube_v1.2` to find process id (pid) of game or other method `pidof`, `pgrep` etc.
3. In new terminal run `scanmem` 
4. in scanmem use command `pid <game pid>`   
5. enter `<value>` you want to track e.g. ammo count 
6. in game change that value e.g. shoot the ammo 
7. enter new `<value>` of what you wanted to track
8. repeat until you have narrowed down matches in scanmem
9. once match found value can be changed using `set <value>`


### Cheat program *ac_rhack* 
Uses cheat program for AssaultCube found at "https://github.com/scannells/ac_rhack"


