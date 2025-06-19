# BPF LAB

This repository provides:

1. Build and boot specific Linux kernel versions
2. Load and test BPF programs
3. Run QEMU-based rootfs with automatic init
4. `git bisect` script to track KASAN behavior

## Overview

```bash
./run.sh setup v5.15      # Prepare kernel worktree for version
./run.sh build v5.15      # Build kernel
./run.sh rootfs           # Create openSUSE rootfs (once)
./run.sh inject v5.15     # Inject BPF/init/module into rootfs
./run.sh qemu v5.15       # Boot into QEMU

# from kernel source
cd src/v5.15
git bisect start
git bisect good
git bisect bad v6.15
git bisect run ../bisect.sh
```
