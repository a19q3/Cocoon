#!/usr/bin/env sh
set -eu

if [ "$#" -lt 1 ]; then
  printf '%s\n' "usage: redox/scripts/qemu.sh path/to/redox.img" >&2
  exit 64
fi

IMAGE="$1"

if [ ! -f "$IMAGE" ]; then
  printf '%s\n' "Redox image not found: $IMAGE" >&2
  exit 66
fi

exec qemu-system-x86_64 \
  -m 1024 \
  -serial stdio \
  -drive "format=raw,file=$IMAGE"
