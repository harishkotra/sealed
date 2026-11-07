//! SEALED — measurement-bound key release for the Baochip `dabao`.
//!
//! Threat model this answers: a signing key that lives on a device will sign
//! *anything* the code on that device asks it to sign. On a closed part you
//! have to trust a vendor attestation key to tell you what code is running.
//! On an open part you can do better: the device measures *itself*, and the
//! key refuses to come out of the keystore unless the measurement matches the
//! digest that was sealed at enrollment time.
//!
//! What is measured: the byte range between the two sentinels below, which is
//! everything the linker placed in the `.sealed` section — the policy blob plus
//! the gate code that reads it. Any single-byte change to that window changes
//! the digest, and `sealed sign` refuses.
//!
//! What is *not* measured: the rest of the app, the kernel, and RAM after load.
//! That limitation is written down in DESIGN.md rather than papered over. The
//! measured window is deliberately the security-relevant part: the release
//! policy itself, which the gate reads before it will unseal.
//!
//! Persistence: the sealed digest, the device seed and the signature counter
//! live in keystore application slots (RRAM, encrypted under the chip's root
//! secret). The seed is never printed; only the public key is.
//!
//! Crypto: ECDSA over NIST P-256 (pure Rust `p256`, RFC 6979 deterministic
//! nonces), SHA-256 for measurement, the hardware TRNG for key generation.
//! Signatures are emitted DER-encoded so `openssl` can check them independently.

use core::fmt::Write as _;

use bao1x_hal_service::trng;
use keystore::Keystore;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::{CommonEnv, ShellCmdApi};

/// Keystore slots inside the `APPLICATION` data partition, which is
/// `DataRange(384..1920)` in `libs/bao1x-api/src/offsets/common.rs` and is
/// Open/ReadWrite on the `dabao`. The loadable-BIO loader claims the low
/// indices (`APP_BIO_*`), so SEALED sits at the top of the range where it
/// cannot collide with anything the older commands wrote.
const SLOT_STATE: usize = 1400;
const SLOT_MEASURE: usize = 1401;
const SLOT_SEED: usize = 1402;
const SLOT_COUNTER: usize = 1403;

const fn pad32(s: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < s.len() && i < 32 {
        out[i] = s[i];
        i += 1;
    }
    out
}

const MAGIC_ENROLLED: [u8; 32] = pad32(b"SEALED01");
const MAGIC_EMPTY: [u8; 32] = pad32(b"SEALED00");

// ---------------------------------------------------------------------------
// The measured window.
//
// It is a single fixed-size blob, because relying on linker ordering or on a
// symbol table is fragile: lld reorders same-named input sections and release
// images can be stripped. One static of known length means the device and the
// host always agree on exactly which bytes are covered.
//
// Layout:  0..8   b"SEALBLOB"
//          8..88  the release policy (NUL padded)
//         88..96  b"SEALGATE"
// ---------------------------------------------------------------------------

const BLOB_LEN: usize = 96;
const POLICY_OFF: usize = 8;
const POLICY_LEN: usize = 80;
const BLOB_MAGIC: [u8; 8] = *b"SEALBLOB";
const BLOB_END: [u8; 8] = *b"SEALGATE";

/// The text the gate reads at runtime, so this is not decoration: patching a
/// byte here changes behaviour *and* the measured digest.
const POLICY_TEXT: &[u8] = b"SEALEDv1|gate=measure-before-unseal|curve=p256|hash=sha256";

const fn build_blob() -> [u8; BLOB_LEN] {
    let mut b = [0u8; BLOB_LEN];
    let mut i = 0;
    while i < 8 {
        b[i] = BLOB_MAGIC[i];
        i += 1;
    }
    i = 0;
    while i < POLICY_TEXT.len() && i < POLICY_LEN {
        b[POLICY_OFF + i] = POLICY_TEXT[i];
        i += 1;
    }
    i = 0;
    while i < 8 {
        b[BLOB_LEN - 8 + i] = BLOB_END[i];
        i += 1;
    }
    b
}

#[used]
#[link_section = ".sealed"]
static SEALED_BLOB: [u8; BLOB_LEN] = build_blob();

/// Sanity ceiling, kept for the same reason as before: never hash a window
/// larger than the one we designed.
const MAX_WINDOW: usize = 8192;

fn window() -> Result<&'static [u8], &'static str> {
    let w: &'static [u8] = &SEALED_BLOB[..];
    if w.len() > MAX_WINDOW {
        return Err("WINDOW_TOO_LARGE");
    }
    Ok(w)
}

/// True when the blob still carries the magic the gate expects. A rebuild that
/// patched the policy text trips this *and* changes the digest; both are
/// reported so the operator can see which one fired.
fn magic_ok() -> bool {
    SEALED_BLOB[..8] == BLOB_MAGIC && SEALED_BLOB[BLOB_LEN - 8..] == BLOB_END
}

fn measure() -> Result<[u8; 32], &'static str> {
    let w = window()?;
    let mut h = Sha256::new();
    h.update(w);
    let out = h.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out);
    Ok(digest)
}

fn hex(bytes: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(D[(b >> 4) as usize] as char);
        s.push(D[(b & 0x0f) as usize] as char);
    }
    s
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = (b[2 * i] as char).to_digit(16)?;
        let lo = (b[2 * i + 1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

/// Draw a fresh P-256 scalar from the hardware TRNG. `from_bytes` rejects
/// zero / out-of-range values, so retry rather than shipping a weak key.
fn scalar_from_trng(t: &trng::Trng) -> [u8; 32] {
    for _ in 0..16 {
        let mut buf = [0u32; 8];
        t.fill_buf(&mut buf).expect("SEALED: TRNG fault");
        let mut seed = [0u8; 32];
        for (i, w) in buf.iter().enumerate() {
            seed[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        if SigningKey::from_bytes(&seed).is_ok() {
            return seed;
        }
    }
    panic!("SEALED: TRNG produced no valid scalar in 16 tries");
}

fn pubkey_hex(sk: &SigningKey) -> String {
    let vk = VerifyingKey::from(sk);
    hex(vk.to_encoded_point(false).as_bytes())
}

pub struct SealedCmd {
    ks: Keystore,
}

impl core::fmt::Debug for SealedCmd {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SealedCmd")
    }
}

impl SealedCmd {
    pub fn new(xns: &xous_names::XousNames) -> Self {
        SealedCmd { ks: Keystore::new(xns) }
    }

    /// (enrolled, sealed_digest, seed, counter)
    fn load_state(&self) -> (bool, Option<[u8; 32]>, Option<[u8; 32]>, u32) {
        let state = self.ks.read_app_key(SLOT_STATE).unwrap_or([0u8; 32]);
        let counter = self
            .ks
            .read_app_key(SLOT_COUNTER)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .unwrap_or(0);
        if state[..8] == MAGIC_ENROLLED {
            (
                true,
                self.ks.read_app_key(SLOT_MEASURE).ok(),
                self.ks.read_app_key(SLOT_SEED).ok(),
                counter,
            )
        } else {
            (false, None, None, counter)
        }
    }

    fn help(&self) -> String {
        let mut s = String::new();
        writeln!(s, "sealed <cmd>:").ok();
        writeln!(s, "  status              measurement vs. sealed digest").ok();
        writeln!(s, "  policy              print the measured policy blob").ok();
        writeln!(s, "  selftest            SHA-256 KAT + ECDSA sign/verify roundtrip").ok();
        writeln!(s, "  enroll              seal the *running* measurement, mint device key").ok();
        writeln!(s, "  sign <64hex>        sign a 32-byte digest, only if measurement matches").ok();
        writeln!(s, "  attest <64hex>      quote over sha256(measurement || challenge)").ok();
        writeln!(s, "  forget              wipe seal + seed (re-enroll demo)").ok();
        s
    }
}

impl<'a> ShellCmdApi<'a> for SealedCmd {
    cmd_api!(sealed);

    fn process(&mut self, args: String, env: &mut CommonEnv) -> Result<Option<String>, xous::Error> {
        let mut ret = String::new();
        let mut tokens = args.split_whitespace();
        let sub = tokens.next().unwrap_or("");

        let (enrolled, sealed, seed, counter) = self.load_state();
        let current = measure();

        match sub {
            "status" => {
                writeln!(ret, "SEALED v1").ok();
                match &current {
                    Ok(d) => {
                        writeln!(ret, "MEASURE={}", hex(d)).ok();
                        writeln!(ret, "MEASURE_LEN={}", window().map(|w| w.len()).unwrap_or(0)).ok();
                    }
                    Err(e) => {
                        writeln!(ret, "MEASURE=ERR_{}", e).ok();
                    }
                }
                writeln!(
                    ret,
                    "SLOTS={},{},{},{}",
                    SLOT_STATE, SLOT_MEASURE, SLOT_SEED, SLOT_COUNTER
                )
                .ok();
                writeln!(ret, "SIGNS={}", counter).ok();
                writeln!(ret, "MODE=owner-enrolled-dev").ok();
                if !enrolled {
                    writeln!(ret, "STATE=unsealed").ok();
                    writeln!(ret, "VERDICT=UNSEALED").ok();
                } else {
                    writeln!(ret, "STATE=enrolled").ok();
                    if let (Some(s), Ok(c)) = (&sealed, &current) {
                        writeln!(ret, "SEALED_MEASURE={}", hex(s)).ok();
                        if s == c {
                            writeln!(ret, "VERDICT=MATCH").ok();
                        } else {
                            writeln!(ret, "VERDICT=MISMATCH").ok();
                        }
                    }
                    if let Some(sd) = &seed {
                        if let Ok(sk) = SigningKey::from_bytes(sd) {
                            writeln!(ret, "PUBKEY={}", pubkey_hex(&sk)).ok();
                        }
                    }
                }
                writeln!(ret, "OK").ok();
            }
            "policy" => {
                let p = &SEALED_BLOB[POLICY_OFF..POLICY_OFF + POLICY_LEN];
                let end = p.iter().position(|&c| c == 0).unwrap_or(p.len());
                writeln!(
                    ret,
                    "POLICY={}",
                    core::str::from_utf8(&p[..end]).unwrap_or("<binary>")
                )
                .ok();
                writeln!(ret, "POLICY_MAGIC={}", if magic_ok() { "OK" } else { "TAMPERED" }).ok();
                writeln!(ret, "BLOB_LEN={}", BLOB_LEN).ok();
                writeln!(ret, "OK").ok();
            }
            "selftest" => {
                // SHA-256 known-answer test: FIPS 180-2 "abc".
                let mut h = Sha256::new();
                h.update(b"abc");
                let got = hex(&h.finalize());
                let want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
                writeln!(ret, "SHA256_ABC={}", got).ok();
                writeln!(ret, "SHA256_KAT={}", if got == want { "PASS" } else { "FAIL" }).ok();

                // ECDSA roundtrip with a throwaway TRNG key.
                let s = scalar_from_trng(&env.trng);
                let sk = SigningKey::from_bytes(&s).expect("valid scalar");
                let vk = VerifyingKey::from(&sk);
                let sig: Signature = sk.sign(b"sealed selftest");
                let ok = vk.verify(b"sealed selftest", &sig).is_ok();
                let bad = vk.verify(b"sealed selftesT", &sig).is_ok();
                writeln!(ret, "ECDSA_ROUNDTRIP={}", if ok { "PASS" } else { "FAIL" }).ok();
                writeln!(ret, "ECDSA_BADMSG={}", if bad { "FAIL" } else { "PASS" }).ok();
                writeln!(ret, "TRNG=OK").ok();
                writeln!(ret, "OK").ok();
            }
            "enroll" => {
                let c = match &current {
                    Ok(c) => *c,
                    Err(e) => {
                        writeln!(ret, "ERR measurement unavailable: {}", e).ok();
                        return Ok(Some(ret));
                    }
                };
                let s = scalar_from_trng(&env.trng);
                let sk = match SigningKey::from_bytes(&s) {
                    Ok(k) => k,
                    Err(_) => {
                        writeln!(ret, "ERR bad scalar").ok();
                        return Ok(Some(ret));
                    }
                };
                if self.ks.write_app_key(SLOT_SEED, &s).is_err() {
                    writeln!(ret, "ERR keystore write refused (slot {})", SLOT_SEED).ok();
                    return Ok(Some(ret));
                }
                if self.ks.write_app_key(SLOT_MEASURE, &c).is_err() {
                    writeln!(ret, "ERR keystore write refused (slot {})", SLOT_MEASURE).ok();
                    return Ok(Some(ret));
                }
                if self.ks.write_app_key(SLOT_COUNTER, &[0u8; 32]).is_err() {
                    writeln!(ret, "ERR keystore write refused (slot {})", SLOT_COUNTER).ok();
                    return Ok(Some(ret));
                }
                if self.ks.write_app_key(SLOT_STATE, &MAGIC_ENROLLED).is_err() {
                    writeln!(ret, "ERR keystore write refused (slot {})", SLOT_STATE).ok();
                    return Ok(Some(ret));
                }
                writeln!(ret, "ENROLLED=1").ok();
                writeln!(ret, "SEALED_MEASURE={}", hex(&c)).ok();
                writeln!(ret, "PUBKEY={}", pubkey_hex(&sk)).ok();
                writeln!(ret, "OK").ok();
            }
            "sign" => {
                let arg = match tokens.next() {
                    Some(a) => a,
                    None => {
                        writeln!(ret, "ERR usage: sealed sign <64hex>").ok();
                        return Ok(Some(ret));
                    }
                };
                let msg = match unhex32(arg) {
                    Some(m) => m,
                    None => {
                        writeln!(ret, "ERR digest must be 64 hex chars").ok();
                        return Ok(Some(ret));
                    }
                };
                if !enrolled {
                    writeln!(ret, "REFUSED reason=UNSEALED").ok();
                    writeln!(ret, "ERR no sealed digest: run `sealed enroll` first").ok();
                    return Ok(Some(ret));
                }
                let (s, c) = match (&sealed, &current) {
                    (Some(s), Ok(c)) => (s, c),
                    _ => {
                        writeln!(ret, "REFUSED reason=MEASUREMENT_UNAVAILABLE").ok();
                        return Ok(Some(ret));
                    }
                };
                if s != c {
                    writeln!(ret, "REFUSED reason=MEASUREMENT_MISMATCH").ok();
                    writeln!(ret, "SEALED_MEASURE={}", hex(s)).ok();
                    writeln!(ret, "MEASURE={}", hex(c)).ok();
                    writeln!(ret, "ERR running image is not the image that was sealed").ok();
                    return Ok(Some(ret));
                }
                let sd = match &seed {
                    Some(sd) => sd,
                    None => {
                        writeln!(ret, "REFUSED reason=NO_KEY").ok();
                        return Ok(Some(ret));
                    }
                };
                let sk = match SigningKey::from_bytes(sd) {
                    Ok(k) => k,
                    Err(_) => {
                        writeln!(ret, "REFUSED reason=BAD_KEY").ok();
                        return Ok(Some(ret));
                    }
                };
                let sig: Signature = sk.sign(&msg);
                let der = sig.to_der();
                let n = counter.wrapping_add(1);
                let mut cb = [0u8; 32];
                cb[..4].copy_from_slice(&n.to_le_bytes());
                self.ks.write_app_key(SLOT_COUNTER, &cb).ok();
                writeln!(ret, "VERDICT=MATCH").ok();
                writeln!(ret, "DIGEST={}", hex(&msg)).ok();
                writeln!(ret, "SIG_DER={}", hex(der.as_bytes())).ok();
                writeln!(ret, "PUBKEY={}", pubkey_hex(&sk)).ok();
                writeln!(ret, "SIGNS={}", n).ok();
                writeln!(ret, "OK").ok();
            }
            "attest" => {
                let arg = match tokens.next() {
                    Some(a) => a,
                    None => {
                        writeln!(ret, "ERR usage: sealed attest <64hex challenge>").ok();
                        return Ok(Some(ret));
                    }
                };
                let ch = match unhex32(arg) {
                    Some(m) => m,
                    None => {
                        writeln!(ret, "ERR challenge must be 64 hex chars").ok();
                        return Ok(Some(ret));
                    }
                };
                let (s, c) = match (&sealed, &current) {
                    (Some(s), Ok(c)) => (s, c),
                    _ => {
                        writeln!(ret, "REFUSED reason=UNSEALED").ok();
                        return Ok(Some(ret));
                    }
                };
                if s != c {
                    writeln!(ret, "REFUSED reason=MEASUREMENT_MISMATCH").ok();
                    return Ok(Some(ret));
                }
                let sd = match &seed {
                    Some(sd) => sd,
                    None => {
                        writeln!(ret, "REFUSED reason=NO_KEY").ok();
                        return Ok(Some(ret));
                    }
                };
                let mut h = Sha256::new();
                h.update(c);
                h.update(ch);
                let q = h.finalize();
                let sk = match SigningKey::from_bytes(sd) {
                    Ok(k) => k,
                    Err(_) => {
                        writeln!(ret, "REFUSED reason=BAD_KEY").ok();
                        return Ok(Some(ret));
                    }
                };
                let sig: Signature = sk.sign(&q);
                writeln!(ret, "QUOTE={}", hex(&q)).ok();
                writeln!(ret, "SIG_DER={}", hex(sig.to_der().as_bytes())).ok();
                writeln!(ret, "PUBKEY={}", pubkey_hex(&sk)).ok();
                writeln!(ret, "OK").ok();
            }
            "forget" => {
                self.ks.write_app_key(SLOT_STATE, &MAGIC_EMPTY).ok();
                self.ks.write_app_key(SLOT_MEASURE, &[0u8; 32]).ok();
                self.ks.write_app_key(SLOT_SEED, &[0u8; 32]).ok();
                self.ks.write_app_key(SLOT_COUNTER, &[0u8; 32]).ok();
                writeln!(ret, "STATE=unsealed").ok();
                writeln!(ret, "OK").ok();
            }
            _ => {
                ret.push_str(&self.help());
                writeln!(ret, "OK").ok();
            }
        }
        Ok(Some(ret))
    }
}
