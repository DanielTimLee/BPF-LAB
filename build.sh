#!/bin/bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

KVER=${KVER:-${1:-v5.15}}
KSRC=$ROOT/src/$KVER
OUT=/dev/stdout
QUIET=${2:-0}
cd $KSRC

if [[ $QUIET -eq 1 ]]; then
	OUT=/dev/null
fi

export MAKEFLAGS="-j$(nproc)"

# Workaround for Linux v5.15 build issue
# Ref: https://unix.stackexchange.com/a/767697
sed -i 's|-fPIC.*|-fPIC -Wno-use-after-free|' tools/lib/subcmd/Makefile

make mrproper           >$OUT

# Use BPF selftest configuration templates as base
GIT_ROOT=$(git worktree list | head -1 | awk '{print $1}')
cat $GIT_ROOT/tools/testing/selftests/bpf/config > .config
cat $GIT_ROOT/tools/testing/selftests/bpf/config.vm >> .config
cat $GIT_ROOT/tools/testing/selftests/bpf/config.x86_64 >> .config

# Enable KVM, KASAN, FP
./scripts/config --enable   CONFIG_KASAN
./scripts/config --enable   CONFIG_PARAVIRT
./scripts/config --enable   CONFIG_KVM_GUEST
./scripts/config --enable   CONFIG_FRAME_POINTER
./scripts/config --enable   CONFIG_HYPERVISOR_GUEST
./scripts/config --enable   CONFIG_UNWINDER_FRAME_POINTER

# Disable RETPOLINE, IBT/KASLR, BTF, ORC
./scripts/config --disable  CONFIG_RETPOLINE          # for JIT-fixup
./scripts/config --disable  CONFIG_UNWINDER_ORC
./scripts/config --disable  CONFIG_X86_KERNEL_IBT
./scripts/config --disable  CONFIG_RANDOMIZE_BASE
./scripts/config --disable  CONFIG_DEBUG_INFO_BTF
./scripts/config --disable  CONFIG_BPF_JIT_ALWAYS_ON
./scripts/config --disable  CONFIG_SECURITY_SELINUX

make olddefconfig       >$OUT
echo "Build Kernel"
make                    >$OUT

# Restore changes
git restore tools/lib/subcmd/Makefile   || true

# generate headers
make headers_install    >$OUT
make -C tools/lib/bpf   >$OUT

cd -
