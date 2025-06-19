#!/bin/bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

KVER=${KVER:-${1:-v5.15}}
KSRC=$ROOT/src/$KVER

mkdir -p $ROOT/src

export DEBIAN_FRONTEND=noninteractive
command -v sudo >/dev/null || sudo() { "$@"; }

sudo apt update
sudo apt install -y build-essential clang llvm flex bison bc git kmod pahole sudo curl \
        rsync lsb-release libncurses-dev libelf-dev libssl-dev universal-ctags qemu-system-x86

if ! command -v docker >/dev/null; then
    curl -fsSL https://get.docker.com | sudo bash
fi

if [[ -f "/.dockerenv"  ]] && ! pgrep dockerd >/dev/null; then
    nohup dockerd >/dev/null 2>&1 &
fi

if [[ ! -d "$ROOT/linux" ]]; then
    git clone git://git.kernel.org/pub/scm/linux/kernel/git/netdev/net-next.git $ROOT/linux
fi

if [[ ! -d "$KSRC" ]]; then
    git -C $ROOT/linux worktree add -B $KVER $KSRC $KVER
fi
