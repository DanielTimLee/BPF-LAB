#!/bin/bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

QUIET=1
MANUAL=0
KVER=$(basename $PWD)
KSRC=$ROOT/src/$KVER
LOG=log-$(git -C $KSRC rev-parse --short HEAD)

$ROOT/build.sh  $KVER $QUIET
$ROOT/inject.sh $KVER
$ROOT/qemu.sh   $KVER $MANUAL

# Kernel panic or build failure, mark as unknown
grep -q "Kernel panic" "$KSRC/$LOG" && exit 125
[[ ! -s "$KSRC/$LOG" ]] && exit 125

# find KASAN from the log
echo "check result: $KSRC/$LOG"
grep -q KASAN "$KSRC/$LOG"
kasan_disappeared=$?

if [[ $kasan_disappeared -eq 1 ]]; then
    echo "KASAN not found"
else
    echo "KASAN detected"
fi

exit $kasan_disappeared
