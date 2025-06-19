#!/bin/bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

KVER=${KVER:-${1:-v5.15}}
KSRC=$ROOT/src/$KVER
MANUAL=${2:-1}
CMDLINE="${3:-}"

LOG=log-$(git -C $KSRC rev-parse --short HEAD)

# set manual=0 for auto shutoff after test
qemu-system-x86_64 -accel kvm -m 512M \
    -append "root=/dev/vda rw console=ttyS0 panic=1 manual=$MANUAL $CMDLINE" \
    -kernel "$KSRC/arch/x86_64/boot/bzImage" \
    -drive file=$ROOT/disk.img,format=raw,if=virtio \
    -nographic -no-reboot | tee $KSRC/$LOG
