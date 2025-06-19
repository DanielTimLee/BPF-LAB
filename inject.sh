#!/bin/bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

KVER=${KVER:-${1:-v5.15}}
KSRC=$ROOT/src/$KVER

DISK=$ROOT/disk.img
ROOTFS=$ROOT/rootfs
BPF_SRC=$ROOT/bpf

if [[ ! -f "$DISK" ]]; then
    echo "'./run.sh rootfs' first!"
    exit 1
fi

if [[ ! -d "src/$KVER" ]]; then
    echo "'./run.sh build $KVER' fisrt!"
    exit 1
fi

mkdir -p $ROOTFS
sudo mount -o loop $DISK $ROOTFS

# BPF progarm compile
for src in $BPF_SRC/*.bpf.c; do
    obj=${src%.c}.o

    [[ -f "$obj"  ]] || clang -O2 -g -target bpf \
        -I $KSRC/usr/include -I $KSRC/tools/lib \
        -c $src -o $obj

	sudo cp $obj $ROOTFS
done

# Kernel module compile
sudo make -C $KSRC modules_install INSTALL_MOD_PATH=$ROOTFS

# Inject init and patch
sed 's|^:$|                                            \
    bpftool prog loadall /out_bound.bpf.o /sys/fs/bpf  \
|' init > .init
sudo cp .init $ROOTFS/sbin/init
sudo chmod +x $ROOTFS/sbin/init

sudo umount $ROOTFS
rmdir $ROOTFS
