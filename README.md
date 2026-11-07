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

$ sealed.py sign --tx tx.bin
REFUSED reason=MEASUREMENT_MISMATCH
SEALED_MEASURE=3eecd519...
MEASURE=84f71c51...
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

# 3. flash: hold PROG, plug in USB, copy loader/xous/apps .uf2, press PROG
#    then talk to it:
python3 sealed/cli/sealed.py selftest
python3 sealed/cli/sealed.py enroll
python3 sealed/cli/sealed.py sign --tx tx.bin
```

Full board procedure, including the tamper drill and a troubleshooting table:
**[RUNBOOK.md](RUNBOOK.md)**.
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
EXPECTED_MEASURE=3eecd519bfeb9e39da607e8aaf7f795c15f6013ef0c200edb5f3941488bbdd8e
# after flipping one byte ("unseal" -> "unseaL") in the policy:
EXPECTED_MEASURE=84f71c51b329b429f9ab261d0a0c91a9e483e4d9232b87ca758b4f6b278716bf
```

Both checkouts also produced byte-identical UF2 sizes (apps 689,664 / loader
242,176 / xous 2,336,256 bytes), which is the "reproducible by the next person"
claim with receipts.

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
| `selftest` | on-device SHA-256 KAT, ECDSA roundtrip, TRNG check |
| `status` | measurement, state, verdict, signature counter |
| `enroll` | seal the current measurement to a fresh TRNG key |
| `sign --tx f` / `--digest h` | gate-and-sign; writes `sealed-signature.json` |
| `attest [--challenge]` | freshness quote over `SHA-256(measurement ‖ challenge)` |
| `policy` | print the measured blob and its magic check |
| `expect --elf f` | compute the expected measurement from a build artifact |
| `dossier [elf] [out.md]` | one-page evidence bundle (device quote vs source rebuild) |
| `forget` | clear the seal (owner re-anchors) |
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

## Status

* Board module builds clean with the Baochip toolchain (1.99.1 + `xtask install-toolkit`).
* Fresh-clone → `apply.py` → build produces all three UF2s; measurement matches the
  published digest on both checkouts.
* Host CLI self-checks pass without any hardware attached (`hostcheck`).
* **Not yet run on physical silicon.** The device-side transcripts in this README
  are the expected output from the code paths, and the runbook's step 4 compares the
  device's `MEASURE=` to the published digest precisely so the first real run
  validates the central claim rather than assuming it.
