#!/bin/sh
# Regenerate every media artifact from the two recorded sessions.
#
#   ./demo/build_demo.sh            # render from existing casts
#   ./demo/build_demo.sh --record   # also re-record against the board
#
# Re-recording needs the board twice: once running the sealed image (part 1),
# once running the one-byte-tampered image (part 2). Set PORT to the app CDC
# port — boot1 enumerates as a different device and cannot answer `sealed`.
set -e
cd "$(dirname "$0")/.."
ROOT=$(pwd)
SEALED="python3 $ROOT/sealed/cli/sealed.py"
: "${PORT:=/dev/cu.usbmodemV6VJDB3}"
REL="$ROOT/xous-core/target/riscv32imac-unknown-xous-elf/release"
export SEALED PORT REL
mkdir -p media

if [ "$1" = "--record" ]; then
  python3 tools/record_demo.py demo/clean.plan  media/demo-part1.cast
  python3 tools/record_demo.py demo/tamper.plan media/demo-part2.cast
fi

python3 tools/render_cast.py --out media/demo --fps 8 \
  --card "SEALED|A signing key that only releases when the board is running the image you published|4" \
  media/demo-part1.cast \
  --card "Part 2 — one byte of policy|Rebuild with a single character changed, flash it, and ask for a signature again|3.5" \
  media/demo-part2.cast \
  --card "Part 3 — the seal does not follow the code|Flash the published image back: the key returns, and the signature counter never reset|3.5" \
  --shot "STATE=enrolled=01-status" \
  --shot "HOST_VERIFY=PASS=02-sign" \
  --shot "CHALLENGE_BOUND=PASS=03-attest" \
  --shot "VERDICT=MISMATCH=04-mismatch" \
  --shot "REFUSED=05-refused"
