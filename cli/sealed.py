#!/usr/bin/env python3
"""
sealed.py — host side of SEALED, the measurement-bound key-release demo for
the Baochip `dabao` board.

The board does the crypto; this script does the talking. No third-party
dependencies: serial is driven through termios and ECDSA P-256 verification is
implemented in ~60 lines of pure Python below (checked against an
openssl-generated vector by `sealed.py hostcheck`).

Typical use
-----------
    ./sealed.py ports                     # find the board's console
    ./sealed.py -p auto status            # measurement vs. sealed digest
    ./sealed.py -p auto enroll            # seal THIS build, mint device key
    ./sealed.py -p auto sign --tx tx.json # refuse or sign, then verify locally
    ./sealed.py -p auto expect --elf <elf># digest the ELF the board should be running
    ./sealed.py -p auto dossier out.md    # one-file evidence report
"""

import argparse
import base64
import hashlib
import json
import os
import select
import struct
import sys
import termios
import time

PROMPT_MARKERS = ("\nOK", "\r\nOK", "OK\r\n")
KEY_LINE = ("MEASURE=", "SEALED_MEASURE=", "VERDICT=", "STATE=", "PUBKEY=",
            "SIG=", "DIGEST=", "SIGNS=", "QUOTE=", "POLICY=", "ENROLLED=",
            "SHA256_KAT=", "ECDSA_ROUNDTRIP=", "SHA256_ABC=", "ECDSA_BADMSG=", "REFUSED",
            "ERR ", "TRNG=", "MEASURE_LEN=", "SLOTS=", "MODE=")


# ---------------------------------------------------------------------------
# serial
# ---------------------------------------------------------------------------
def serial_ports():
    cands = []
    for d in ("/dev",):
        try:
            for n in sorted(os.listdir(d)):
                if n.startswith(("cu.usbmodem", "cu.usbserial", "ttyACM", "ttyUSB")):
                    cands.append(os.path.join(d, n))
        except OSError:
            pass
    return cands


def pick_port(port):
    if port in (None, "auto"):
        cands = serial_ports()
        if not cands:
            sys.exit("no USB serial port found — is the board plugged in and booted?")
        if len(cands) > 1:
            print("multiple ports, using", cands[0], "(override with -p)", file=sys.stderr)
        return cands[0]
    return port


def open_port(a):
    return Serial(pick_port(a.port), a.baud)


class Serial:
    def __init__(self, path, baud=termios.B115200):
        self.fd = os.open(path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        a = termios.tcgetattr(self.fd)
        a[0] = 0                                     # iflag: raw
        a[1] = 0                                     # oflag: raw
        a[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
        a[3] = 0                                     # lflag: no echo, no canon
        a[4] = baud
        a[5] = baud
        a[6][termios.VMIN] = 0
        a[6][termios.VTIME] = 0
        termios.tcsetattr(self.fd, termios.TCSANOW, a)
        termios.tcflush(self.fd, termios.TCIOFLUSH)

    def close(self):
        try:
            os.close(self.fd)
        except OSError:
            pass

    def write(self, s):
        os.write(self.fd, s.encode())

    def read_until_ok(self, timeout=12.0):
        """Read until the shell echoes a lone OK line, or we time out."""
        buf = b""
        deadline = time.time() + timeout
        quiet_since = None
        while time.time() < deadline:
            r, _, _ = select.select([self.fd], [], [], 0.1)
            if not r:
                # The console's prompt string is not part of any stability
                # contract, so we also accept "the line went quiet" as done.
                if buf and quiet_since is None:
                    quiet_since = time.time()
                elif quiet_since and time.time() - quiet_since > 0.45:
                    break
                continue
            try:
                chunk = os.read(self.fd, 4096)
            except OSError:
                break
            if not chunk:
                continue
            quiet_since = None
            buf += chunk
            text = buf.decode("utf-8", "replace")
            if any(m in text for m in PROMPT_MARKERS):
                break
        return buf.decode("utf-8", "replace")

    def read_ack(self, timeout=4.0, quiet=0.30):
        """Read until one of the boot1 uf2 acks shows up, then stop."""
        buf = b""
        deadline = time.time() + timeout
        last = time.time()
        while time.time() < deadline:
            r, _, _ = select.select([self.fd], [], [], 0.02)
            if r:
                try:
                    chunk = os.read(self.fd, 8192)
                except OSError:
                    break
                if chunk:
                    buf += chunk
                    last = time.time()
                    t = buf.decode("utf-8", "replace").lower()
                    if ("wrote" in t) or ("invalid write address" in t) or ("corrupt base64" in t) or ("write error" in t):
                        return buf.decode("utf-8", "replace")
            elif buf and time.time() - last > quiet:
                break
        return buf.decode("utf-8", "replace")

    def command(self, line, timeout=12.0):
        self.write(line + "\r")
        raw = self.read_until_ok(timeout)
        return parse(raw)


def parse(raw):
    """Pull KEY=VALUE lines out of the noisy serial transcript."""
    out = {"_raw": raw, "_lines": []}
    for ln in raw.replace("\r", "\n").split("\n"):
        ln = ln.strip()
        if not ln:
            continue
        if any(ln.startswith(k) or ln.startswith("OK") or ln.startswith("REFUSED") for k in KEY_LINE):
            out["_lines"].append(ln)
        if "=" in ln and not ln.startswith("sealed "):
            k, _, v = ln.partition("=")
            k = k.strip().split()[-1]
            v = v.strip()
            if k and v and " " not in k:
                out[k] = v
        elif ln.startswith("REFUSED"):
            out["REFUSED"] = ln[len("REFUSED"):].strip()
    return out


# ---------------------------------------------------------------------------
# ECDSA over NIST P-256 (verification only), pure Python, no deps.
# Cross-checked against the openssl-generated vector in KAT_* below by
# `sealed.py hostcheck`; run that first if a signature ever looks wrong.
# ---------------------------------------------------------------------------
P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
P256_A = P256_P - 3
P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
P256_GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
P256_GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
P256_G = (P256_GX, P256_GY)

# Generated once with openssl (prime256v1) over the ASCII message
# "sealed hostcheck". Used only to prove this verifier is correct.
KAT_PUB = bytes.fromhex(
    "04e646f1ecffdfb5c96055cffb9dc1cec788fa4b83da3c972cd82743d53ad523a4"
    "b7125d77549b071fe0b303443e7673f84430723685842df6ebc8dbce6306e6fe")
KAT_MSG = b"sealed hostcheck"
KAT_SIG = bytes.fromhex(
    "3046022100dfef50ec125d2cb0c5c7b8878eb8a88ab5bf6ef4a6db65558ca88d17e05a7277"
    "022100e175bd529ef7fbb30b24e598001979861cf04e8e438e0ab6c4abcfac3c25c4b0")


def _p256_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P256_P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + P256_A) * pow(2 * y1, P256_P - 2, P256_P) % P256_P
    else:
        lam = (y2 - y1) * pow(x2 - x1, P256_P - 2, P256_P) % P256_P
    x3 = (lam * lam - x1 - x2) % P256_P
    return (x3, (lam * (x1 - x3) - y1) % P256_P)


def _p256_mul(pt, k):
    acc = None
    while k:
        if k & 1:
            acc = _p256_add(acc, pt)
        pt = _p256_add(pt, pt)
        k >>= 1
    return acc


def _p256_on_curve(pt):
    if pt is None:
        return False
    x, y = pt
    return (y * y - (x * x * x + P256_A * x + P256_B)) % P256_P == 0


def _parse_der_sig(der):
    if len(der) < 8 or der[0] != 0x30:
        raise ValueError("not a DER SEQUENCE")
    i = 2
    if der[1] & 0x80:
        i = 2 + (der[1] & 0x7F)
    if der[i] != 0x02:
        raise ValueError("expected INTEGER r")
    rlen = der[i + 1]
    r = int.from_bytes(der[i + 2:i + 2 + rlen], "big")
    i = i + 2 + rlen
    if der[i] != 0x02:
        raise ValueError("expected INTEGER s")
    slen = der[i + 1]
    s = int.from_bytes(der[i + 2:i + 2 + slen], "big")
    return r, s


def _decode_pub(pub):
    if len(pub) == 65 and pub[0] == 0x04:
        return (int.from_bytes(pub[1:33], "big"), int.from_bytes(pub[33:], "big"))
    if len(pub) == 64:
        return (int.from_bytes(pub[:32], "big"), int.from_bytes(pub[32:], "big"))
    raise ValueError("expected a 65-byte uncompressed SEC1 point")


def p256_verify(pub, msg, der):
    """Verify a DER-encoded ECDSA signature over msg (hashed with SHA-256)."""
    try:
        r, s = _parse_der_sig(der)
        if not (1 <= r < P256_N and 1 <= s < P256_N):
            return False
        Q = _decode_pub(pub)
        if not _p256_on_curve(Q):
            return False
    except (ValueError, IndexError):
        return False
    z = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    w = pow(s, -1, P256_N)
    pt = _p256_add(_p256_mul(P256_G, z * w % P256_N),
                   _p256_mul(Q, r * w % P256_N))
    if pt is None:
        return False
    return pt[0] % P256_N == r


def hostcheck():
    ok = p256_verify(KAT_PUB, KAT_MSG, KAT_SIG)
    bad = p256_verify(KAT_PUB, KAT_MSG + b"!", KAT_SIG)
    print("P256_KAT_VERIFY=%s" % ("PASS" if ok else "FAIL"))
    print("P256_KAT_REJECT=%s" % ("PASS" if not bad else "FAIL"))
    return ok and not bad


# ---------------------------------------------------------------------------
# ELF: recompute the digest the board should report, from the ELF it runs
# ---------------------------------------------------------------------------
BLOB_MAGIC = b"SEALBLOB"
BLOB_LEN = 96


def elf_sealed_range(path):
    """Locate the SEALED blob in a built app and hash exactly the bytes the
    device hashes.

    The blob is found by its 8-byte magic rather than by symbol name, because
    lld reorders same-named input sections and release images can be stripped.
    `SEALBLOB` happens to appear once in the image; we assert that.
    """
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"\x7fELF":
        raise SystemExit("%s: not an ELF" % path)
    hits = [i for i in range(len(data)) if data.startswith(BLOB_MAGIC, i)]
    if len(hits) != 1:
        raise SystemExit(
            "%s: expected exactly one SEALBLOB magic, found %d. "
            "Is this the app built with the SEALED module?" % (path, len(hits)))
    off = hits[0]
    blob = data[off:off + BLOB_LEN]
    if blob[-8:] != b"SEALGATE":
        raise SystemExit("%s: blob is truncated or the end magic is wrong" % path)
    return blob, hashlib.sha256(blob).hexdigest()


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------
def need(res, key):
    if key not in res:
        print(res.get("_raw", ""), file=sys.stderr)
        sys.exit("board did not answer with %s (see transcript above)" % key)
    return res[key]


def cmd_status(s, args):
    r = s.command("sealed status")
    for ln in r["_lines"]:
        print(ln)
    return 0 if r.get("VERDICT") else 1


def cmd_enroll(s, args):
    r = s.command("sealed enroll")
    for ln in r["_lines"]:
        print(ln)
    return 0 if r.get("ENROLLED") else 1


def cmd_selftest(s, args):
    r = s.command("sealed selftest", timeout=25)
    for ln in r["_lines"]:
        print(ln)
    ok = r.get("SHA256_KAT") == "PASS" and r.get("ECDSA_ROUNDTRIP") == "PASS"
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# UF2-over-serial flashing
#
# The board exposes a USB mass-storage volume for UF2 files, but macOS can deny
# a non-interactive process access to removable volumes. boot1 also accepts UF2
# blocks one at a time on the console (`uf2 <base64>`), which needs no volume
# permissions. This sends the same blocks the volume copy would have written.
# ---------------------------------------------------------------------------
UF2_MAGIC0 = 0x0A324655
UF2_MAGIC1 = 0x9E5D5157
UF2_MAGIC_END = 0x0AB16F30


def uf2_blocks(path):
    data = open(path, "rb").read()
    if len(data) % 512:
        raise SystemExit("%s: not a UF2 file (size not a multiple of 512)" % path)
    out = []
    for off in range(0, len(data), 512):
        b = data[off:off + 512]
        m0, m1 = struct.unpack("<II", b[0:8])
        if m0 != UF2_MAGIC0 or m1 != UF2_MAGIC1 or struct.unpack("<I", b[508:512])[0] != UF2_MAGIC_END:
            raise SystemExit("%s: bad UF2 magic at block %d" % (path, off // 512))
        addr, size = struct.unpack("<II", b[12:20])
        out.append((addr, size, b))
    return out


def cmd_flash(s, args):
    blocks = uf2_blocks(args.uf2)
    print("UF2=%s" % args.uf2)
    print("BLOCKS=%d" % len(blocks))
    lo = min(a for a, _, _ in blocks)
    hi = max(a + n for a, n, _ in blocks)
    print("RANGE=0x%08x..0x%08x" % (lo, hi))
    if args.dry_run:
        print("DRY_RUN=1")
        return 0

    t0 = time.time()
    done = 0
    retries = 0
    for idx, (addr, size, raw) in enumerate(blocks):
        b64 = base64.b64encode(raw).decode("ascii")
        ok = False
        for attempt in range(args.retries):
            s.write("uf2 " + b64 + "\r")
            resp = s.read_ack(4.0)
            low = resp.lower()
            if "corrupt base64" in low or "decode error" in low:
                continue
            if "invalid write address" in low:
                raise SystemExit("block %d @0x%08x rejected: invalid write address" % (idx, addr))
            if ("wrote" in low) or ("write error" in low):
                if "write error" in low:
                    raise SystemExit("block %d @0x%08x: %s" % (idx, addr, resp.strip()))
                ok = True
                break
            retries += 1
        if not ok:
            raise SystemExit("block %d @0x%08x: no ack after %d tries" % (idx, addr, args.retries))
        done += 1
        if args.progress and (done % args.progress == 0 or done == len(blocks)):
            el = time.time() - t0
            rate = done / el if el else 0
            eta = (len(blocks) - done) / rate if rate else 0
            print("PROGRESS=%d/%d rate=%.1f blk/s eta=%.0fs" % (done, len(blocks), rate, eta),
                  flush=True)
    el = time.time() - t0
    print("WROTE=%d" % done)
    print("RETRIES=%d" % retries)
    print("SECONDS=%.1f" % el)
    print("OK")
    return 0


def cmd_monitor(s, args):
    """Dump the raw serial transcript for a while. Use this to watch the boot
    messages, to confirm the shell prompt, or to talk to the boot1 console
    before Xous starts (nothing is sent by this command)."""
    deadline = time.time() + args.seconds
    try:
        while time.time() < deadline:
            r, _, _ = select.select([s.fd], [], [], 0.25)
            if not r:
                continue
            chunk = os.read(s.fd, 4096)
            if chunk:
                sys.stdout.write(chunk.decode("utf-8", "replace"))
                sys.stdout.flush()
    except KeyboardInterrupt:
        pass
    return 0


def cmd_send(s, args):
    """Send one raw line and print everything that comes back, unfiltered."""
    s.write(args.line + "\r")
    time.sleep(args.wait)
    out = b""
    while True:
        r, _, _ = select.select([s.fd], [], [], 0.2)
        if not r:
            break
        chunk = os.read(s.fd, 4096)
        if not chunk:
            break
        out += chunk
    print(out.decode("utf-8", "replace"))
    return 0


def cmd_hostcheck(s, args):
    return 0 if hostcheck() else 1


def cmd_policy(s, args):
    r = s.command("sealed policy")
    for ln in r["_lines"]:
        print(ln)
    return 0


def cmd_forget(s, args):
    r = s.command("sealed forget")
    for ln in r["_lines"]:
        print(ln)
    return 0


def cmd_attest(s, args):
    challenge = args.challenge or os.urandom(32).hex()
    r = s.command("sealed attest " + challenge)
    for ln in r["_lines"]:
        print(ln)
    if "SIG_DER" not in r:
        return 1
    ok = p256_verify(bytes.fromhex(r["PUBKEY"]), bytes.fromhex(r["QUOTE"]), bytes.fromhex(r["SIG_DER"]))
    print("HOST_VERIFY=%s" % ("PASS" if ok else "FAIL"))
    # Bind the quote to *this* challenge. The device's console line editor
    # silently drops an immediately-repeated byte, so a mangled argument would
    # otherwise still produce a perfectly valid signature over the wrong quote.
    st = s.command("sealed status")
    meas = st.get("SEALED_MEASURE") or st.get("MEASURE")
    bound = hashlib.sha256(bytes.fromhex(meas) + bytes.fromhex(challenge)).hexdigest() == r["QUOTE"]
    print("CHALLENGE=%s" % challenge)
    print("CHALLENGE_BOUND=%s" % ("PASS" if bound else "FAIL"))
    return 0 if (ok and bound) else 1


def cmd_sign(s, args):
    if args.tx:
        with open(args.tx, "rb") as f:
            payload = f.read()
        digest = hashlib.sha256(payload).hexdigest()
        print("TX_FILE=%s" % args.tx)
    elif args.digest:
        digest = args.digest.lower()
    else:
        sys.exit("give --tx <file> or --digest <64hex>")
    print("HOST_DIGEST=%s" % digest)

    r = s.command("sealed sign " + digest)
    for ln in r["_lines"]:
        print(ln)
    if "SIG_DER" not in r:
        print("RESULT=REFUSED")
        return 2
    pub = bytes.fromhex(r["PUBKEY"])
    sig = bytes.fromhex(r["SIG_DER"])
    ok = p256_verify(pub, bytes.fromhex(digest), sig)
    print("HOST_VERIFY=%s" % ("PASS" if ok else "FAIL"))
    if args.out:
        with open(args.out, "w") as f:
            json.dump({"digest": digest, "signature_der": r["SIG_DER"], "pubkey": r["PUBKEY"],
                       "verified": ok, "signs": r.get("SIGNS")}, f, indent=2)
        print("WROTE=%s" % args.out)
    return 0 if ok else 1


def cmd_expect(s, args):
    blob, digest = elf_sealed_range(args.elf)
    print("ELF=%s" % args.elf)
    print("WINDOW_LEN=%d" % len(blob))
    print("EXPECTED_MEASURE=%s" % digest)
    print("POLICY=%s" % blob[8:88].rstrip(b"\0").decode("utf-8", "replace"))
    return 0


def cmd_dossier(s, args):
    lines = ["# SEALED dossier", ""]
    st = s.command("sealed status")
    lines.append("## Device")
    lines += ["- `%s`" % ln for ln in st["_lines"]]
    verdict = st.get("VERDICT", "UNKNOWN")
    dev_measure = st.get("MEASURE")
    if args.elf:
        try:
            _, exp = elf_sealed_range(args.elf)
            lines += ["", "## Rebuilt-from-source check",
                      "- ELF: `%s`" % args.elf,
                      "- expected: `%s`" % exp,
                      "- device:   `%s`" % dev_measure,
                      "- **%s**" % ("ELF matches the running image" if exp == dev_measure
                                    else "ELF DOES NOT MATCH the running image")]
        except SystemExit as e:
            lines.append("- ELF check failed: %s" % e)
    lines += ["", "## Verdict", "", "`%s`" % verdict]
    text = "\n".join(lines) + "\n"
    if args.out:
        with open(args.out, "w") as f:
            f.write(text)
        print("WROTE=%s" % args.out)
    else:
        print(text)
    return 0 if verdict == "MATCH" else 1


def main():
    ap = argparse.ArgumentParser(description="SEALED host CLI for the Baochip dabao")
    ap.add_argument("-p", "--port", default="auto", help="serial device or 'auto'")
    ap.add_argument("--baud", type=int, default=115200)
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("ports")
    sub.add_parser("status")
    sub.add_parser("enroll")
    sub.add_parser("selftest")
    sub.add_parser("policy")
    sub.add_parser("hostcheck")
    p_fl = sub.add_parser("flash", help="write a UF2 file over the boot1 serial console")
    p_fl.add_argument("--uf2", required=True)
    p_fl.add_argument("--dry-run", action="store_true")
    p_fl.add_argument("--progress", type=int, default=100)
    p_fl.add_argument("--retries", type=int, default=3)
    p_mon = sub.add_parser("monitor", help="dump raw serial output, send nothing")
    p_mon.add_argument("--seconds", type=float, default=8.0)
    p_snd = sub.add_parser("send", help="send one raw line and print the reply")
    p_snd.add_argument("line")
    p_snd.add_argument("--wait", type=float, default=1.5)
    sub.add_parser("forget")
    p = sub.add_parser("sign")
    p.add_argument("--tx")
    p.add_argument("--digest")
    p.add_argument("--out", default="sealed-signature.json")
    p = sub.add_parser("attest")
    p.add_argument("--challenge")
    p = sub.add_parser("expect")
    p.add_argument("--elf", required=True)
    p = sub.add_parser("dossier")
    p.add_argument("elf", nargs="?")
    p.add_argument("out", nargs="?")
    a = ap.parse_args()

    if a.cmd == "ports":
        ps = serial_ports()
        for p in ps:
            print(p)
        if not ps:
            print("(no USB serial ports found — plug the board in. On macOS expect "
                  "/dev/cu.usbmodem*)")
        return 0

    if a.cmd is None:
        ap.print_help()
        return 1

    if a.cmd == "flash":
        sfl = Serial(pick_port(a.port), a.baud)
        try:
            return cmd_flash(sfl, a)
        finally:
            sfl.close()

    if a.cmd == "monitor":
        return cmd_monitor(open_port(a), a)

    if a.cmd == "send":
        return cmd_send(open_port(a), a)

    if a.cmd == "hostcheck":
        return cmd_hostcheck(None, a)

    if a.cmd == "expect":
        return cmd_expect(None, a)

    s = Serial(pick_port(a.port), a.baud)
    try:
        fn = {"status": cmd_status, "enroll": cmd_enroll, "selftest": cmd_selftest,
              "policy": cmd_policy, "forget": cmd_forget, "sign": cmd_sign,
              "attest": cmd_attest, "dossier": cmd_dossier}[a.cmd]
        return fn(s, a)
    finally:
        s.close()


if __name__ == "__main__":
    sys.exit(main())
