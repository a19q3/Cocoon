#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
SMOKE_DIR="$ROOT/target/redox-smoke"
OVERLAY_DIR="$SMOKE_DIR/overlay/capsules"
CAPSULE="$SMOKE_DIR/hello-service.cocoon"

mkdir -p "$OVERLAY_DIR"

if [ ! -f "$CAPSULE" ]; then
  cargo run -p cocoon-cli -- build examples/hello-service --output "$CAPSULE"
fi

cargo run -p cocoon-cli -- verify "$CAPSULE"
cargo run -p cocoon-cli -- plan "$CAPSULE"
cp "$CAPSULE" "$OVERLAY_DIR/hello-service.cocoon"

printf '%s\n' "Prepared Redox overlay scaffold at $SMOKE_DIR/overlay"
printf '%s\n' "Set REDOX_CHECKOUT and extend this script to inject the overlay into a Redox image."
