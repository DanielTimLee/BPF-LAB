#!/bin/bash

# tumbleweed for latest bpftool
ID=$(docker run -itd opensuse/tumbleweed:latest /bin/bash)
docker exec -i $ID bash <<'EOF'
    zypper mr -d -G -all > /dev/null
    zypper mr -e repo-oss

    zypper --non-interactive install --recommends bpftool libbpf1 busybox jq
    for i in $(cat /usr/share/busybox/busybox.links); do
        ln -s /usr/bin/busybox $i 2>/dev/null
    done
    zypper clean --all
    rm -rf .dockerenv
EOF

# Generate disk image and copy rootfs
dd if=/dev/zero of=disk.img bs=1M count=1000
mkfs.ext4 disk.img

mkdir rootfs
sudo mount -o loop disk.img rootfs

docker export $ID | sudo tar -x -C rootfs/
docker rm -f $ID

sudo umount rootfs
rmdir rootfs
