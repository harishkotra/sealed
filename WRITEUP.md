# A signer that refuses

*A trust layer for open hardware, built on the Baochip Dabao. Hackathon write-up.*

---

## The uncomfortable thing about hardware wallets

Ask a hardware wallet what it's running and it will answer with a signature. The
signature is only meaningful if you know *what* produced it — which usually means
trusting a vendor's attestation key baked in at the factory.

Dabao has no factory attestation key for third-party apps. Baochip is explicit
about this: they publish the RTL, the boot chain and the app source, and they hand
you a chip, not a certificate chain. At Nicolas Bacca's "Ethereum Signer on Dabao"
workshop the three open problems named were exactly this: no screen, no attestation
key, and the fact that loading a development app permanently flips the chip into
developer mode.

"Just trust the vendor" is not available here. So what is available?

## Self-measurement instead of vendor attestation

SEALED adds two things to the stock Xous console app:

1. **A measured window.** A 96-byte blob, marked with magic at both ends, holding
   the release policy as text. The device hashes it with SHA-256.
2. **A gate.** The signing key is stored in the keystore, and it is only decrypted
   when the freshly computed digest equals the digest sealed at enrollment.

Enrollment happens once, by the owner, on first boot: the device hashes its own
window, draws a P-256 key from the hardware TRNG, and stores
`{state, digest, seed, signature counter}` in the keystore's application partition.
Only the public key comes back out.

From then on, every signature is conditional. Change one byte of that policy text,
rebuild, flash the app — and the device still boots, still responds to commands,
still prints its policy, and refuses to sign:

```
$ sealed.py status
MEASURE=84f71c51...          <- what is running
SEALED_MEASURE=3eecd519...   <- what the owner sealed
VERDICT=MISMATCH

$ sealed.py sign --tx tx.bin
REFUSED reason=MEASUREMENT_MISMATCH
SEALED_MEASURE=3eecd519...
MEASURE=84f71c51...
ERR running image is not the image that was sealed
```

The keystore seed is never loaded into a signing key in that path. Refusal costs the
device nothing but honesty.

Because the sealed state lives in RRAM-backed keystore slots rather than in the app
binary, reflashing `apps.uf2` does not reset it — that is what makes the demo a real
attack rather than a build-time check. Restoring the good image restores
`VERDICT=MATCH` with the *same* `PUBKEY`, which is the proof that the identity is
device state, not app state.

## Why a blob and not a symbol range

The first version measured from a `SEALED_BEGIN` sentinel to a `SEALED_END`
sentinel using the ELF symbol table on the host. It failed in two instructive ways:
lld reordered the same-named input sections, so `SEALED_END` ended up *below*
`SEALED_BEGIN` and the range was empty; and release images get stripped, so a
symbol-driven host check cannot find the window at all.

A fixed-length blob with magic at both ends removes the ambiguity. The device hashes
`&BLOB[..96]`. The host scans the ELF for `SEALBLOB`, asserts it appears exactly
once, and hashes the same 96 bytes. Two independent checkouts of the same source
produce the same digest, and the same UF2 byte counts — which is the "reproducible
by the next person" claim with receipts rather than adjectives.

The policy text is parsed at runtime, so the measured bytes are the gate's
instructions. It is not a decorative constant that a host tool compares for fun.

## Honesty section

What SEALED does *not* do, in the same font size as what it does:

* **It does not measure the rest of the app or the kernel.** Only the policy blob is
  in the window. A hostile app can do anything else it likes; what it cannot do is
  get the seed released.
* **It does not survive a compromised kernel**, a debug probe, or a DMA engine
  writing over the mapped blob before the check (`DESIGN.md` §8).
* **It is not vendor attestation.** It proves "this is the image you enrolled", not
  "this is the image Baochip signed". Owner-enrolled, self-measured — and if the
  owner enrolls a hostile image, the device will sign for it.
* **The counter is not anti-rollback.** It counts signatures; it does not ratchet the
  image. A real design would bind the digest to a hardware monotonic counter, which
  needs loader support.
* **The hardware crypto accelerators are unused.** Hashing and ECDSA are Rust
  (`sha2`, `p256`) for auditability. The keystore, TRNG, MMU, RRAM and kernel *are*
  load-bearing; the BIO and the accelerators are not. The README says the same thing
  in its silicon table, because a table that claims everything is a table that says
  nothing.
* **Developer mode is flipped.** Flashing this development image moves boot1's
  next-stage signing key from `2/2 (beta)` to `3/3 (dev)`, visible in `audit`. That is reported, not hidden: this is a hackathon
  board running hackathon software, and any attestation story built on it should say
  so out loud.

The point of publishing the limitations is that a trust claim you cannot falsify is
marketing. SEALED's claim is narrow and checkable: *the owner's seal is enforced
against the owner's measurement, on hardware the owner can audit.*

## What the hardware said

The build proved the code compiled. The board decided whether the claim was true, and
it found two things the compiler could not.

The first was mine: `state[..8] == MAGIC_ENROLLED` compares an 8-byte slice against a
32-byte array. Rust happily compiles that comparison and it is always false, so
`status` kept reporting `unsealed` on a device that had enrolled correctly. The
keystore was fine the whole time — `sealed probe` showed the slot holding
`5345414c45443031` (`"SEALED01"`) and a `WRITE_RT=OK` / `READ_RT=a5a5…` roundtrip
before I touched anything else. It is now a full-slot comparison.

The second is a property of the console, not of SEALED: its serial line editor
mangles repeated bytes in the echo, and once silently truncated a 66-character
argument to 64. The device still parsed and answered correctly, but a demo that
trusts the echo could publish a signature over a digest nobody asked for. So the CLI
now re-derives the quote from the challenge it sent (`CHALLENGE_BOUND=PASS`) and
verifies the signature against the digest it requested, which makes a mangled
argument a hard failure instead of a silent wrong answer.

Everything else held. On real silicon: `SHA256_KAT=PASS`, `ECDSA_ROUNDTRIP=PASS`,
`ECDSA_BADMSG=PASS`, `TRNG=OK`, `MEASURE=3eecd519…dd8e` — the same digest the host
computes from the ELF — `STATE=enrolled` survives a reboot *and* an `apps.uf2`
replacement (`SIGNS=1` carried across the reflash), and a one-byte policy edit moves
the measurement to `44c9cb13…c627`, at which point `sign` answers
`REFUSED reason=MEASUREMENT_MISMATCH`.

One honest side effect: boot1's `audit` now reads `Next stage: key 3/3 (dev)`, since
the image is signed with the development key. Nothing is revoked — a stock beta-signed
image still verifies — but the board's lifecycle state moved because of this project,
and the write-up says so.

## The demo

Ninety seconds, one terminal, no screen:

1. `status` → `VERDICT=MATCH`; read the digest aloud as the hash of the published policy.
2. `sign --tx tx.bin` → `HOST_VERIFY=PASS`, verified by 60 lines of stdlib Python.
3. Cut to the one-byte edit and the rebuild.
4. Flash `apps.uf2`, `status` → `VERDICT=MISMATCH`.
5. `sign` → `REFUSED reason=MEASUREMENT_MISMATCH`. Let the silence sit.
6. Revert, reflash, `status` → `VERDICT=MATCH`, same `PUBKEY`, counter incremented.
7. `dossier out.md` → device quote and source-rebuild measurement on one page.

## Reproduce it

```sh
cargo +1.99.1 xtask install-toolkit --force --no-verify
git clone https://github.com/betrusted-io/xous-core && cd xous-core
python3 ../sealed/scripts/apply.py --xous .
CI=true cargo +1.99.1 xtask dabao dabao-console --no-verify
python3 ../sealed/cli/sealed.py expect --elf target/riscv32imac-unknown-xous-elf/release/dabao-console
```

`RUNBOOK.md` has the board steps (plug in, flash three images over boot1's serial
`uf2` command, `boot`), the tamper drill, and the troubleshooting table. `DESIGN.md` has the threat
model.

---

Nothing in this design needs a Baochip signing key, a manufacturer database, or a
network connection. It needs an open chip that can measure itself and a console that
is willing to say no. That is what an open chip is for.

*— SEALED, built at Devcon 8 Mumbai.*
