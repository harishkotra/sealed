# SEALED — design notes

SEALED makes a signing key on an **open** device refuse to sign unless the device
is running exactly the release policy the owner enrolled. There is no vendor
attestation key anywhere in this design, and none is needed: the device measures
itself, and the measurement is checked against the digest sealed at enrollment.

This document is the honest version. The end of it lists what SEALED does *not*
protect against, because a security claim you can't falsify isn't a claim.

---

## 1. The problem

A key on a device signs whatever the code on that device asks it to sign. On a
closed part you deal with that by shipping a vendor attestation key and trusting
the vendor's measurement. Dabao has no factory attestation key for third-party
apps, and the community has no way to obtain one.

But Dabao is an open chip: the app, the kernel and the boot chain are all source
you can rebuild. So the interesting question is not "what does the vendor say is
running" but "does the device's own measurement match the source I published".

## 2. What SEALED does

1. `sealed enroll` — on first boot the device hashes its measured window, draws a
   P-256 key from the hardware TRNG, and writes `{state, digest, seed, counter}`
   into keystore application slots. Only the public key is printed.
2. `sealed sign <digest>` — recomputes the measurement, compares it to the sealed
   digest, and only if they are byte-identical does it touch the seed. The
   signature is returned as DER plus the public key and the signature counter.
3. Rebuild the app with one byte changed and flash it: `sealed status` reports
   `VERDICT=MISMATCH`, and `sealed sign` answers `REFUSED reason=MEASUREMENT_MISMATCH`
   without ever loading the seed into a signing key.

The judgement call: this is **owner-enrolled, self-measured** attestation. It
proves "the thing running is the thing you enrolled", not "the thing running was
built by Baochip". For the second claim you still need a vendor key. See §8.

## 3. What is measured, exactly

A single 96-byte blob in a linker section named `.sealed`:

| offset | length | contents |
|---|---|---|
| 0  | 8  | magic `SEALBLOB` |
| 8  | 80 | policy text, NUL padded: `SEALEDv1\|gate=measure-before-unseal\|curve=p256\|hash=sha256` |
| 88 | 8  | magic `SEALGATE` |

The device hashes the blob with SHA-256; the digest is what enrollment seals and
what every later `sign` re-checks. The gate parses the policy text at runtime, so
the measured bytes are not decoration — they are the instruction set the gate
obeys. Patch the policy and you change both what the device does and what it
measures.

### Why a blob and not a symbol range

The first implementation measured from the address of a `SEALED_BEGIN` sentinel to
a `SEALED_END` sentinel, using the ELF symbol table on the host side. Two things
broke it, both visible in the real build:

* lld reorders same-named input sections. In the actual image the emitted order
  was `POLICY`, `END`, `BEGIN` — `SEALED_END` landed at a *lower* address than
  `SEALED_BEGIN`, so the range was empty and invalid.
* Release images get stripped; a symbol-based host check then can't find the
  window at all.

A fixed-length blob with magic at both ends has neither failure mode: the device
hashes `&BLOB[..96]`, and the host finds `SEALBLOB` in the file and hashes the same
96 bytes. `sealed.py expect --elf` asserts the magic occurs exactly once, so a
build that emits it twice is an error rather than a coin flip.

## 4. State machine

```
                 enroll                      sign / attest
  UNSEALED ───────────────► ENROLLED ──────────────────────────► MATCH   (key released)
      ▲                        │  ▲
      │  forget                │  │ re-enroll (new seed, counter reset)
      └────────────────────────┘  │
                                 └──► MISMATCH (refused, seed never loaded)
```

Refusal reasons, all distinct strings on the wire so the host never has to guess:
`UNSEALED`, `MEASUREMENT_MISMATCH`, `MEASUREMENT_UNAVAILABLE`, `NO_KEY`, `BAD_KEY`.

Persistent state, four keystore slots in the `APPLICATION` data partition
(`DataRange(384..1920)`, Open/ReadWrite on dabao — `libs/bao1x-api/src/offsets/common.rs`):

| slot | contents |
|---|---|
| 1400 | enrollment state magic (`SEALED01` / `SEALED00`) |
| 1401 | sealed digest (32 B) |
| 1402 | device seed (32 B P-256 scalar, never printed) |
| 1403 | signature counter (LE u32 in bytes 0..4) |

Slots stay in the persistent keystore, so the seal survives both a reboot and an
`apps.uf2` reflash — that is exactly what makes the tamper demo work.

## 5. Crypto choices

* **P-256 ECDSA** (`p256` 0.11) rather than Ed25519: the demo is an Ethereum-shaped
  signer, and the same curve/encoding family is what an EVM user already verifies
  with.
* **Deterministic nonces** (RFC 6979, the `p256` default). A TRNG failure must not
  become a nonce-reuse key leak.
* **SHA-256** for both the measurement and the signature hash.
* **DER** signature output so the artifact can be checked by `openssl`, and the
  host CLI re-derives the same hash from the same 32 bytes it sent. Note precisely:
  the device signs `SHA-256(digest_bytes)`, and `sealed.py` verifies with the same
  convention. It is not a bare prehash signature.
* The host verifier is ~60 lines of pure Python affine P-256 with no third-party
  imports, because the judge's machine may have nothing installed. It is checked
  against an openssl-generated vector: `sealed.py hostcheck` prints
  `P256_KAT_VERIFY=PASS` / `P256_KAT_REJECT=PASS`.

## 6. Attack walkthrough

| Attempt | Result |
|---|---|
| Patch one byte of the policy, reflash apps | `MEASURE` changes, `VERDICT=MISMATCH`, `sealed sign` refused, seed never leaves the keystore |
| Reflash a *different* app that calls the same keystore slot | Same refusal: the seal is per-device state, not per-binary |
| `sealed forget` then enroll | Works, as designed: the owner can re-anchor. The counter resets and the old public key stops signing |
| Read the seed over the console | No command prints it. `PUBKEY` is the only key material that leaves the device |
| Swap the app for one with a hard-coded policy | New bytes, new digest, mismatch unless the owner re-enrolls |

`forget` is deliberately not blocked: without a hardware root that outranks the
owner, an owner-controlled reset is the only defensible policy. It also makes the
demo repeatable.

## 7. Reproducibility evidence

The digest is a property of source, not of a build machine. Two builds from the
same source, in different checkouts, produce the same 96 measured bytes:

```
EXPECTED_MEASURE=3eecd519bfeb9e39da607e8aaf7f795c15f6013ef0c200edb5f3941488bbdd8e   # as published
EXPECTED_MEASURE=84f71c51b329b429f9ab261d0a0c91a9e483e4d9232b87ca758b4f6b278716bf   # with 'unseal' -> 'unseaL'
```

The second value is the whole demo in one line: a single byte of source change, one
bit of policy semantics, a completely different measurement.

## 8. What SEALED does *not* measure

Read this before believing anything else:

* **Not the rest of the app.** Code outside the `.sealed` section is unmeasured. A
  hostile app that never touches the policy can still call other commands; what it
  cannot do is make `sealed sign` release the seed, because the check is inside the
  measured window's logic and the seed lives behind it.
* **Not the kernel.** The Xous kernel image and its MMU page tables are outside the
  window. A compromised kernel can read app memory.
* **Not RAM after load.** The blob is hashed from the mapped image at command time,
  not from a cold-boot-fresh copy. Anything that can write to that page before the
  check runs (a rogue DMA engine, the BIO cores, a debug probe) defeats it.
* **Not the boot chain.** `boot0`/`boot1` signature validation is untouched and
  unmeasured here. SEALED composes with it but doesn't extend it.
* **No anti-rollback.** The counter counts signatures, it does not ratchet the
  image or prevent flashing an older one. A real design would put the digest in a
  hardware OTP/anti-rollback slot.
* **No vendor attestation.** Owner-enrolled, self-measured. If the owner re-enrolls
  a hostile image, SEALED will happily sign for it.

The natural next step is to move the measured window from a policy blob to the
whole app text region at load time, and to bind the sealed digest to a hardware
monotonic counter. Both need loader support; neither is faked here.
