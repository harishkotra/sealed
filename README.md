# SEALED

**A signing key that refuses to sign when the device it lives on isn't running the image you published.**

Built for the Baochip / Dabao hackathon (Devcon 8). Runs on the board, headless,
driven entirely from a Mac over USB serial.

```
$ sealed.py status
SEALED v1
MEASURE=3eecd519bfeb9e39da607e8aaf7f795c15f6013ef0c200edb5f3941488bbdd8e
STATE=enrolled
VERDICT=MATCH
OK

$ sealed.py sign --tx tx.bin
VERDICT=MATCH
SIG_DER=3045022100...
PUBKEY=04b1f8...
SIGNS=1
HOST_VERIFY=PASS

# ... now change one byte of the release policy, rebuild, flash apps.uf2 ...

$ sealed.py status
MEASURE=44c9cb139733065c9d92f70990fe0a64f4804da7564a9c21389703e489b1c627
STATE=enrolled
SEALED_MEASURE=3eecd519bfeb9e39da607e8aaf7f795c15f6013ef0c200edb5f3941488bbdd8e
VERDICT=MISMATCH

$ sealed.py sign --tx tx.bin
REFUSED reason=MEASUREMENT_MISMATCH
SEALED_MEASURE=3eecd519...
MEASURE=44c9cb13...
ERR running image is not the image that was sealed
RESULT=REFUSED
```

That last transcript is the project. The device did not ask a server, a vendor, or
the host whether it was trustworthy. It hashed its own measured window, found that
it no longer matched what the owner sealed, and declined to unseal the key.

## Why this, on this chip

A hardware signer's weak point is that it signs what the software on it asks it to
sign. Closed vendors fix that with a factory attestation key. **Dabao has no
third-party attestation key and never will** — so SEALED takes the only honest
route available on an open chip: the owner enrolls a measurement on first boot, and
every signature is gated on the device still measuring the same thing.

There is no vendor to trust here, and that is the point. The chip is open source,
the app is open source, the measurement is reproducible on your machine, and the
verification code on the host is 60 lines of dependency-free Python.

## Silicon used

| Block | How SEALED uses it |
|---|---|
| **Keystore (RRAM-backed)** | Device seed, sealed digest, enrollment state and signature counter live in the `APPLICATION` data partition (`DataRange(384..1920)`), so the seal survives reboot *and* `apps.uf2` reflash |
| **TRNG** | P-256 scalar for the device identity, drawn from the hardware entropy source |
| **VexRiscv + MMU** | The measured window is app memory mapped by the Xous kernel; the signing key never appears in any host-visible buffer |
| **RRAM** | Persistence of the seal across reflash — the property that makes the tamper demo real rather than a build-time check |
| **Xous microkernel** | Process isolation, keystore service, serial console; SEALED is a console command inside the stock `dabao-console` app |
| **Crypto accelerators** | *Not used, deliberately.* Hashing and ECDSA run in Rust (`sha2`, `p256`) for auditability; the hardware paths are the obvious next step and are called out in `DESIGN.md` |
| **BIO / I/O coprocessor** | *Not used.* SEALED is a trust-layer project; the BIO is the right place to look for the next attack story (see `DESIGN.md` §8) |
| **IRIS / RTL** | Source-level claim: the whole measurement story is checkable against published RTL and the published app source |

The honest summary: keystore, TRNG, MMU, RRAM and the kernel are genuinely load-
bearing. The crypto accelerators and the BIO are not, and the write-up says so.

## Quick start

```sh
# 1. build (Xous target comes from the Baochip Rust fork)
cargo +1.99.1 xtask install-toolkit --force --no-verify
cd xous-core && CI=true cargo +1.99.1 xtask dabao dabao-console --no-verify

# 2. verify the measured window matches the published digest
python3 sealed/cli/sealed.py expect --elf \
  target/riscv32imac-unknown-xous-elf/release/dabao-console

# 3. flash over serial (macOS blocks the BAOCHIP volume from non-interactive
#    processes, so the CLI speaks boot1's `uf2 <base64>` console command instead)
python3 sealed/cli/sealed.py -p /dev/cu.usbmodem<BOOT1> flash \
  --uf2 target/riscv32imac-unknown-xous-elf/release/loader.uf2
#    repeat for xous.uf2 then apps.uf2, then:
python3 sealed/cli/sealed.py -p /dev/cu.usbmodem<BOOT1> send boot
#    talk to it on the *new* port (it re-enumerates on handoff):
python3 sealed/cli/sealed.py selftest
python3 sealed/cli/sealed.py enroll
python3 sealed/cli/sealed.py sign --tx tx.bin
```

Full board procedure, including the tamper drill and a troubleshooting table:
**[RUNBOOK.md](RUNBOOK.md)**. Ninety-second recording script: **[DEMO.md](DEMO.md)**.
Threat model and the list of things this does *not* protect against:
**[DESIGN.md](DESIGN.md)**.

## What is measured

One 96-byte blob, hashed with SHA-256:

```
[ 0.. 8)  b"SEALBLOB"
[ 8..88)  "SEALEDv1|gate=measure-before-unseal|curve=p256|hash=sha256"  (NUL padded)
[88..96)  b"SEALGATE"
```

The gate parses that text at runtime, so the measured bytes are the gate's
instructions, not a decorative constant. The device hashes the blob in RAM; the host
hashes the same 96 bytes in the ELF; `expect --elf` asserts the magic appears
exactly once so a duplicated blob is a hard error.

Reproducibility, measured on two independent checkouts of the same source:

```
# clean policy
EXPECTED_MEASURE=3eecd519bfeb9e39da607e8aaf7f795c15f6013ef0c200edb5f3941488bbdd8e
# after flipping one byte ("unseal" -> "unsea1") in the policy:
EXPECTED_MEASURE=44c9cb139733065c9d92f70990fe0a64f4804da7564a9c21389703e489b1c627
```

Both numbers were confirmed three ways: computed from the ELF on the host, reported
by the device as `MEASURE=`, and (for the clean build) reproduced byte-for-byte —
rebuilding from a clean tree yields an identical `apps.uf2`
(`sha256 6d8dfecacea8cbac03747b29c232d8cb01e0b2a3a78b6733b4f8d5eb2c9ab4e7`).

## Host CLI

`sealed/cli/sealed.py` — Python 3, standard library only. No `pip install`, no
serial driver package, no crypto library: it opens the serial device with `termios`
directly and verifies ECDSA P-256 in pure Python. `sealed.py hostcheck` checks that
verifier against an openssl-generated vector before you trust it.

| Command | Purpose |
|---|---|
| `ports` | list USB serial devices |
| `monitor --seconds N` | dump the raw serial transcript (boot logs, bootloader console) |
| `send <line>` | send one raw line, print everything back |
| `flash --uf2 f` | write an image over boot1's serial `uf2` command (`--dry-run` parses blocks) |
| `selftest` | on-device SHA-256 KAT, ECDSA roundtrip, TRNG check |
| `status` | measurement, state, verdict, signature counter |
| `enroll` | seal the current measurement to a fresh TRNG key |
| `sign --tx f` / `--digest h` | gate-and-sign; writes `sealed-signature.json` |
| `attest [--challenge]` | freshness quote over `SHA-256(measurement ‖ challenge)` |
| `policy` | print the measured blob and its magic check |
| `expect --elf f` | compute the expected measurement from a build artifact |
| `dossier [elf] [out.md]` | one-page evidence bundle (device quote vs source rebuild) |
| `forget` | clear the seal (owner re-anchors) |
| `send "sealed probe"` | device-side keystore diagnostics (slot reads + write/read roundtrip) |
| `hostcheck` | validate the host-side P-256 verifier |

## Layout

```
sealed/
  board/sealed.rs       the SealedCmd console command (+ measured blob, gate, keystore state)
  cli/sealed.py         host CLI, stdlib only
  scripts/apply.py      idempotent graft onto a stock xous-core checkout (and --revert)
  DESIGN.md             threat model, what is and isn't measured
  RUNBOOK.md            board bring-up and the tamper drill, step by step
```

`scripts/apply.py --xous <checkout>` touches exactly three files: it copies
`board/sealed.rs` to `apps-dabao/dabao-console/src/cmds/`, wires the module into
`cmds.rs`, and adds `p256` + `sha2` to the app's `Cargo.toml`. Running it twice is a
no-op; `--revert` removes it.

## Verified on hardware

Every number below is from a Dabao running the sealed image, driven over USB-C from
a Mac, captured at 2026-11-09.

```
sealed selftest    SHA256_ABC=ba7816bf...  SHA256_KAT=PASS  ECDSA_ROUNDTRIP=PASS
                   ECDSA_BADMSG=PASS  TRNG=OK
sealed enroll      PERSIST=OK  ENROLLED=1
                   PUBKEY=041277c6c58f2386c299c843d55e6ee5ec0389b3d329e997383ca2acb8ace759...
sealed status      MEASURE=3eecd519...dd8e  STATE=enrolled  VERDICT=MATCH  SIGNS=1
sealed sign f17f... VERDICT=MATCH  SIG_DER=3045022100bd933bbb...  SIGNS=1
sealed attest 7ea3.. QUOTE=d392741c...30e6
sealed probe       PROBE_STATE=5345414c45443031...  WRITE_RT=OK  READ_RT=a5a5...
```

Host side, from those exact transcripts: `HOST_VERIFY=True` for the signature,
`False` when one byte of the message is flipped, and the quote recomputed as
`sha256(measurement ‖ challenge)` matches the device byte-for-byte.

Tamper drill on the same board: flash an image whose policy differs by one byte,
reboot, and the seal does not follow it —

```
MEASURE=44c9cb139733065c9d92f70990fe0a64f4804da7564a9c21389703e489b1c627
SEALED_MEASURE=3eecd519bfeb9e39da607e8aaf7f795c15f6013ef0c200edb5f3941488bbdd8e
VERDICT=MISMATCH
REFUSED reason=MEASUREMENT_MISMATCH
```

`SIGNS=1` in the tampered run is the same counter from before the reflash: the
keystore state survives `apps.uf2` replacement, which is what makes the refusal a
statement about the seal rather than about a rebuild.

Two bugs the hardware found that the build could not:

* `state[..8] == MAGIC_ENROLLED` compares an 8-byte slice against a 32-byte array;
  Rust accepts it and the comparison is always false, so `status` reported
  `unsealed` on a device that was enrolled. Fixed to compare the full slot.
* The console's serial line editor mangles repeated bytes in its *echo* (and once
  truncated a 66-character argument to 64). The device's own output lines are
  authoritative, and the CLI now refuses to trust a signature unless it also
  re-derives the quote from the challenge it sent (`CHALLENGE_BOUND=`).

## Status

* Board module builds clean with the Baochip toolchain (1.99.1 + `xtask install-toolkit`).
* Fresh-clone → `apply.py` → build produces all three UF2s; the measurement matches
  the published digest on both checkouts, and a clean rebuild is byte-identical.
* Host CLI self-checks pass without any hardware attached (`hostcheck`).
* **Run on physical silicon**: measurement parity, enroll/persist, sign, attest and
  the tamper refusal are all verified on a Dabao (transcripts above).
* Honest limits: no factory attestation key exists on this part, so the trust anchor
  is the owner's own enrollment; the signing path runs in Rust, not the crypto
  accelerators; loading a dev-signed image flips boot1's next-stage key identity to
  `3/3 (dev)` (visible in `audit`, reversible by flashing a stock image).
