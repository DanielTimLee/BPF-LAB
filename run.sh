#!/bin/bash
CMD=$1
KVER=${2:-v5.15}
MANUAL=1
CMDLINE="$3"

case $CMD in
  setup)  ./setup.sh 	$KVER ;;
  build)  ./build.sh 	$KVER ;;
  rootfs) ./rootfs.sh         ;;
  inject) ./inject.sh 	$KVER ;;
  qemu)   ./qemu.sh 	$KVER $MANUAL "$CMDLINE" ;;
  *) echo "Usage: $0 {setup|build|rootfs|inject|qemu} [ver=v5.15] [cmdline]" ;;
esac
