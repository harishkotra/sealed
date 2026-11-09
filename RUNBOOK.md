# RUNBOOK — SEALED on a real Dabao, no screen

Everything below is done from the Mac. The board never needs a display: it
enumerates a USB mass-storage volume for flashing and a USB serial console for
talking to it. The host CLI (`sealed/cli/sealed.py`) does all the talking.

Total time: ~20 minutes the first pass, ~4 minutes to repeat.

---

## 0. What you need

* The Dabao board and a **USB-C data cable** (charge-only cables are the #1 cause
  of "the volume never appears").
* This repo (the `sealed/` directory) and the build tree
  `~/code/sealed-workspace/xous-core`.
* macOS. `python3` is enough — the CLI has zero third-party dependencies.

Set a shell variable to save typing:

```sh
cd ~/code/sealed-workspace
alias sealed="python3 $PWD/sealed/cli/sealed.py"
```

---

## 1. Build the image

The Xous target comes from a Baochip Rust fork, so it must be installed once per
machine (already done on this Mac; repeat on a new machine):

```sh
cargo +1.99.1 xtask install-toolkit --force --no-verify
```

Then build the app + kernel + loader:

```sh
cd ~/code/sealed-workspace/xous-core
CI=true cargo +1.99.1 xtask dabao dabao-console --no-verify
```

`CI=true` matters: without it the build tries to derive a version from `git
describe`, and a shallow clone with no tags aborts at the signing step.

You should end with three artifacts:

```
target/riscv32imac-unknown-xous-elf/release/loader.uf2
target/riscv32imac-unknown-xous-elf/release/xous.uf2
target/riscv32imac-unknown-xous-elf/release/apps.uf2
```

Sanity-check the measured window before you flash anything:

```sh
python3 sealed/cli/sealed.py expect --elf \
  target/riscv32imac-unknown-xous-elf/release/dabao-console
```

Expected:

```
WINDOW_LEN=96
EXPECTED_MEASURE=3eecd519bfeb9e39da607e8aaf7f795c15f6013ef0c200edb5f3941488bbdd8e
POLICY=SEALEDv1|gate=measure-before-unseal|curve=p256|hash=sha256
```

Write that digest down. It is the value the device must print back in step 4.

---

## 2. Flash the board

1. **Plug in the USB-C cable.** A Dabaos returns to boot1 on plug-in, so a plain
   replug is usually enough. If it boots the installed app instead, hold `PROG`
   (nearest the USB connector) and press `RESET` (farthest), releasing `PROG` once
   the port enumerates.

   ```sh
   ls /dev/cu.usbmodem*      # boot1 shows up as one of these
   ls /Volumes | grep BAOCHIP
   ```

2. **Flash over the serial console, not the volume.** macOS denies non-interactive
   processes access to the `BAOCHIP` removable volume (`Operation not permitted`),
   and writes to it hang. boot1 exposes a `uf2 <base64>` console command that takes
   the same 512-byte blocks, so the CLI speaks that instead:

   ```sh
   P=/dev/cu.usbmodem$(ls /dev/cu.usbmodem* | sed 's|.*cu.usbmodem||' | head -1)
   REL=~/code/sealed-workspace/xous-core/target/riscv32imac-unknown-xous-elf/release
   python3 sealed/cli/sealed.py -p $P flash --uf2 $REL/loader.uf2
   python3 sealed/cli/sealed.py -p $P flash --uf2 $REL/xous.uf2
   python3 sealed/cli/sealed.py -p $P flash --uf2 $REL/apps.uf2
   ```

   First flash needs all three so loader, kernel and app are the same revision;
   after that `apps.uf2` alone is enough (~3 s). `flash --dry-run` validates the
   block structure and prints the base address without touching the board.

3. **Boot it** and note that the port re-enumerates on handoff:

   ```sh
   python3 sealed/cli/sealed.py -p $P send boot
   sleep 6; ls /dev/cu.usbmodem*   # the app is on a *different* suffix
   ```

> ⚠️ Two hard rules:
> * **Never unplug while an image is being written.** Let the `wrote` acks finish;
>   interrupting is what bricks boards. The CLI prints `RETRIES`, `SECONDS`, `OK`.
> * Loading a development image moves boot1's next-stage signing key from
>   `2/2 (beta)` to `3/3 (dev)` — visible in `audit`, nothing revoked, reversible by
>   flashing a stock image. Report it honestly in the write-up; see step 3a.

### 3a. Record the lifecycle state (before flashing, while in bootloader mode)

While the board is in bootloader mode it also exposes its own console. Capture the
boot log once so the write-up can state the pre-flash state rather than assume it:

```sh
python3 sealed/cli/sealed.py ports          # find the /dev/cu.usbmodem* node
python3 sealed/cli/sealed.py monitor --seconds 5
```

Keep that transcript. If the bootloader console accepts input, `sealed.py send
audit` will print its idea of the current state; if the command isn't recognised it
will just echo help, which is also fine to keep.

---

## 3. Find the console and confirm the shell answers

After the app boots, the USB serial device re-enumerates (it disappears and comes
back — that is normal):

```sh
python3 sealed/cli/sealed.py ports
```

Then check you are talking to the Xous shell:

```sh
python3 sealed/cli/sealed.py send help
```

You should see the console's command list, which now includes `sealed`.

If you get silence, run `sealed.py monitor --seconds 5` while the board boots to
see whether the kernel is printing at all.

---

## 4. Prove the silicon works before touching the seal

```sh
python3 sealed/cli/sealed.py selftest
```

Expected, all on-device:

```
SHA256_ABC=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
SHA256_KAT=PASS
ECDSA_ROUNDTRIP=PASS
ECDSA_BADMSG=PASS
TRNG=OK
OK
```

`ECDSA_BADMSG=PASS` means a *modified* message fails verification — the check is
actually checking. `TRNG=OK` means the hardware entropy source produced a valid
P-256 scalar.

Now the state, which must be unsealed on a fresh board:

```sh
python3 sealed/cli/sealed.py status
```

```
SEALED v1
MEASURE=3eecd519bfeb9e39da607e8aaf7f795c15f6013ef0c200edb5f3941488bbdd8e
MEASURE_LEN=96
SLOTS=1400,1401,1402,1403
SIGNS=0
MODE=owner-enrolled-dev
STATE=unsealed
VERDICT=UNSEALED
OK
```

**Compare `MEASURE=` with the `EXPECTED_MEASURE=` from step 1.** They must be
identical. That equality is the whole "rebuild from source and check the device"
claim; if they differ, stop and tell me — it means the blob isn't byte-identical
in RAM and the measurement story needs fixing before anything else.

---

## 5. Enroll

```sh
python3 sealed/cli/sealed.py enroll
```

```
ENROLLED=1
SEALED_MEASURE=3eecd519bfeb9e39da607e8aaf7f795c15f6013ef0c200edb5f3941488bbdd8e
PUBKEY=04...
OK
```

`PUBKEY` is the device identity from here on. The seed behind it is in the
keystore and no command prints it.

---

## 6. Sign — the happy path

```sh
printf 'transfer 1 ETH to 0xabc' > /tmp/tx.bin
python3 sealed/cli/sealed.py sign --tx /tmp/tx.bin
```

```
TX_FILE=/tmp/tx.bin
HOST_DIGEST=<sha256 of the file>
VERDICT=MATCH
DIGEST=<the same digest>
SIG_DER=3045...
PUBKEY=04...
SIGNS=1
OK
HOST_VERIFY=PASS
```

`HOST_VERIFY=PASS` is the host independently verifying the device's signature with
its own pure-Python P-256 verifier. Run it a second time: `SIGNS=` increments, which
is the monotonic counter.

Freshness check — this is what makes the quote non-replayable:

```sh
python3 sealed/cli/sealed.py attest
```

```
QUOTE=<sha256(measurement||challenge)>
SIG_DER=...
PUBKEY=...
HOST_VERIFY=PASS
CHALLENGE=<the random challenge used>
```

---

## 7. Tamper test — the demo

Change **one byte of the release policy** in source, rebuild, and flash only the app:

```sh
cd ~/code/sealed-workspace
python3 - <<'EOF'
p = 'xous-core/apps-dabao/dabao-console/src/cmds/sealed.rs'
s = open(p).read()
assert 'gate=measure-before-unseal' in s
open(p, 'w').write(s.replace('gate=measure-before-unseal', 'gate=measure-before-unseaL'))
print("policy patched: unseal -> unseaL")
EOF

cd xous-core
CI=true cargo +1.99.1 xtask dabao dabao-console --no-verify
```

Confirm the source-level measurement moved:

```sh
python3 ~/code/sealed-workspace/sealed/cli/sealed.py expect --elf \
  target/riscv32imac-unknown-xous-elf/release/dabao-console
# EXPECTED_MEASURE=84f71c51b329b429f9ab261d0a0c91a9e483e4d9232b87ca758b4f6b278716bf
```

Flash **only** `apps.uf2` (plug/replug into boot1, then):

```sh
P=/dev/cu.usbmodem$(ls /dev/cu.usbmodem* | sed 's|.*cu.usbmodem||' | head -1)
python3 sealed/cli/sealed.py -p $P flash \
  --uf2 xous-core/target/riscv32imac-unknown-xous-elf/release/apps.uf2
python3 sealed/cli/sealed.py -p $P send boot
```

Now:

```sh
python3 sealed/cli/sealed.py status
# MEASURE=84f71c51...        <- the running image
# SEALED_MEASURE=3eecd519... <- what was enrolled
# VERDICT=MISMATCH

python3 sealed/cli/sealed.py sign --tx /tmp/tx.bin
# REFUSED reason=MEASUREMENT_MISMATCH
# SEALED_MEASURE=3eecd5...
# MEASURE=84f71c...
# ERR running image is not the image that was sealed
# RESULT=REFUSED
```

The keystore seed was never loaded. That is the entire pitch: **the device refuses,
and it refuses because the bytes changed, not because a server said so.**

Two extra beats worth showing on camera:

* `python3 sealed/cli/sealed.py policy` still prints the tampered text with
  `POLICY_MAGIC=OK` — proving the refusal came from the digest, not from a
  string comparison the attacker could fix.
* `python3 sealed/cli/sealed.py sign --digest <same digest>` — same refusal. The
  gate is not bypassable by changing *what* you ask to sign.

---

## 8. Restore the good image

```sh
cd ~/code/sealed-workspace
python3 - <<'EOF'
p = 'xous-core/apps-dabao/dabao-console/src/cmds/sealed.rs'
s = open(p).read()
open(p, 'w').write(s.replace('gate=measure-before-unseaL', 'gate=measure-before-unseal'))
print("policy reverted")
EOF

cd xous-core
CI=true cargo +1.99.1 xtask dabao dabao-console --no-verify
```

Flash `apps.uf2` again, then:

```sh
python3 sealed/cli/sealed.py status
# VERDICT=MATCH        <- the seal survived two reflashes
# PUBKEY=04...         <- same identity as step 5

python3 sealed/cli/sealed.py sign --tx /tmp/tx.bin
# HOST_VERIFY=PASS, SIGNS increments
```

Same `PUBKEY` after reflashing is the proof that the seal lives in RRAM-backed
keystore state, not in the app binary.

---

## 9. Recording the video

One terminal, one take, ~90 seconds:

1. `sealed.py status` — `VERDICT=MATCH`, read the `MEASURE` out loud as "the digest
   of my published policy".
2. `sealed.py sign --tx /tmp/tx.bin` — `HOST_VERIFY=PASS`.
3. Cut to the one-byte edit + `cargo xtask` rebuild (speed it up 8x).
4. Flash, then `sealed.py status` → `VERDICT=MISMATCH`.
5. `sealed.py sign` → `REFUSED reason=MEASUREMENT_MISMATCH`. Let the pause sit.
6. `sealed.py dossier out.md` — shows the device quote vs the value rebuilt from
   source in one page.

Say the framing out loud once: *"this is owner-enrolled self-measurement, not
vendor attestation — there is no factory key on this board, and there doesn't need
to be."*

---

## 10. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| No `/Volumes` entry after plugging in | Not in bootloader mode, or charge-only cable | Hold `PROG` *while* plugging in; try another cable/port |
| `cp` to `/Volumes/BAOCHIP` says `Operation not permitted` | macOS TCC blocks removable volumes for non-interactive processes | Use `sealed.py flash` (boot1's serial `uf2` command) instead of the volume |
| `sealed` answers on the other port after a reset | boot1 and the Xous app enumerate as different CDC devices | Re-run `ls /dev/cu.usbmodem*` after every `boot` |
| A long command echoes back mangled | The console line editor mangles repeated bytes in its echo | Trust the device's own output lines; the CLI re-checks the quote (`CHALLENGE_BOUND=`) |
| `no USB serial port found` | App crashed on boot, or still in bootloader | Plug cycle; check `sealed.py monitor` during boot |
| Port exists, `send help` silent | Console not up yet, or port busy | Close `screen`/other terminals; wait 2s after the port appears |
| `sealed` prints help instead of acting | Old `apps.uf2` still installed | Reflash `apps.uf2` (loader/kernel unchanged) |
| `ERR keystore write refused` | Keystore service not up, or slot blocked | Reboot; if it persists, check lifecycle/developer state from step 3a |
| `REFUSED reason=MEASUREMENT_UNAVAILABLE` | Window sentinel guard tripped | Report the `status` transcript — do not re-enroll over it |
| Build stops at `SemVer` / `no major version` | Shallow clone without tags | Prefix the build with `CI=true` |
| `install-toolkit` complains | Xous target missing on a fresh machine | Re-run step 1 |

## 11. What to send me back

Paste the transcripts of: `selftest`, the first `status` (before enroll), `enroll`,
`sign`, the tampered `status` and `sign`, and the final `status` + `sign`. If
`MEASURE` ever disagrees with `EXPECTED_MEASURE`, stop there — that is the one
assumption this design has not yet been able to test without hardware.
