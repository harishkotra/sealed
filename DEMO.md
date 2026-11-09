# Demo — 90 seconds, one terminal, no screen

Board state at the start: flashed, enrolled, `VERDICT=MATCH`, on
`/dev/cu.usbmodemV6VJDB3` (the app's CDC port; boot1 is a different suffix).

## The five beats

**1. What is running (10 s)**

```sh
python3 sealed/cli/sealed.py status
```

```
SEALED v1
MEASURE=3eecd519bfeb9e39da607e8aaf7f795c15f6013ef0c200edb5f3941488bbdd8e
STATE=enrolled
SEALED_MEASURE=3eecd519bfeb9e39da607e8aaf7f795c15f6013ef0c200edb5f3941488bbdd8e
VERDICT=MATCH
PUBKEY=041277c6...
```

Say: that digest is the SHA-256 of the 96-byte policy blob inside this app. It is not
a server's opinion — the board hashed its own memory.

**2. The key works, and the host checks it without trusting the device (20 s)**

```sh
echo "payment 42" > tx.bin
python3 sealed/cli/sealed.py sign --tx tx.bin
```

```
VERDICT=MATCH
SIG_DER=3045...
PUBKEY=041277c6...
SIGNS=3
HOST_VERIFY=PASS
```

`HOST_VERIFY` is 60 lines of standard-library Python re-implementing ECDSA P-256.
No `pip install`, no crypto library, nothing to take on faith.

**3. Change one byte (20 s — this can be pre-recorded or cut)**

```sh
sed -i '' 's/gate=measure-before-unseal/gate=measure-before-unsea1/' \
  xous-core/apps-dabao/dabao-console/src/cmds/sealed.rs
cd xous-core && CI=true cargo +1.99.1 xtask dabao dabao-console --no-verify
```

**4. Flash the impostor image (~15 s, needs the board in boot1)**

Unplug/replug the USB-C cable, then:

```sh
P=/dev/cu.usbmodem$(ls /dev/cu.usbmodem* | sed 's|.*cu.usbmodem||' | head -1)
python3 sealed/cli/sealed.py -p $P flash \
  --uf2 target/riscv32imac-unknown-xous-elf/release/apps.uf2
python3 sealed/cli/sealed.py -p $P send boot
sleep 6 && python3 sealed/cli/sealed.py status
```

```
MEASURE=44c9cb13...
SEALED_MEASURE=3eecd519...
VERDICT=MISMATCH
```

**5. Ask for a signature anyway (15 s)** — this is the moment.

```sh
python3 sealed/cli/sealed.py sign --tx tx.bin
```

```
REFUSED reason=MEASUREMENT_MISMATCH
SEALED_MEASURE=3eecd519bfeb9e39da607e8aaf7f795c15f6013ef0c200edb5f3941488bbdd8e
MEASURE=44c9cb139733065c9d92f70990fe0a64f4804da7564a9c21389703e489b1c627
ERR running image is not the image that was sealed
RESULT=REFUSED
```

No network. No vendor. The board compared what it measures now against what the owner
sealed, and declined. `SIGNS` did not move — the key was never released.

**6. Restore (optional, 15 s)** — replug, flash the clean `apps.uf2`, `status` shows
`VERDICT=MATCH`, same `PUBKEY`, counter continues.

## Evidence artifact

```sh
python3 sealed/cli/sealed.py dossier \
  xous-core/target/riscv32imac-unknown-xous-elf/release/dabao-console out.md
```

One page: device measurement, the digest recomputed from the ELF, and the verdict.
Drop it in the submission as the receipt for the video.

## Rules that keep the recording honest

- The device's own output lines are authoritative. The console mangles repeated bytes
  in its *echo*; never read a value off the echoed command line.
- Always pass the port explicitly; boot1 and the app are different `/dev` entries and
  the app's device changes after every reset.
- If a command prints `REFUSED reason=UNSEALED`, the board is on a different image than
  the one that was enrolled — that is the demo, not a failure, but re-enroll before
  recording so the first beat starts from `MATCH`.
