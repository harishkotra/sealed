#!/usr/bin/env python3
"""Render asciicast v2 recordings into a video (mp4 + gif) and PNG stills.

The cast files are produced by tools/record_demo.py from real board sessions, so
this script only decides how they look. Frames are drawn as SVG (monospace, no
font packages needed) and rasterised with ImageMagick, then encoded with ffmpeg.

Usage:
    render_cast.py --out media/demo \
        --card "SEALED|A signing key that refuses to sign when the board is not running the image you published|3.5" \
        media/demo-part1.cast \
        --card "Part 2|one byte of policy changes the measurement — and the key will not move|3" \
        media/demo-part2.cast

Outputs <out>.mp4, <out>.gif, and <out>-NN.png stills at each segment boundary.
"""
import json
import os
import re
import shutil
import subprocess
import sys

W, H = 1200, 700
COLS, ROWS = 112, 28
FS = 15.0
CHAR_W = 9.02
LINE_H = 21.5
LEFT, TOP = 22, 74
MAX_LINES = ROWS

ANSI = re.compile(r"\x1b\[([0-9;]*)m")
STYLES = {"0": "#c9d1d9", "2": "#6b7a90", "31": "#ff7b72", "1;32": "#7ee787"}


def parse_ansi(text, style="#c9d1d9"):
    """Split a line into [(text, colour)] runs."""
    runs, pos = [], 0
    for m in ANSI.finditer(text):
        if m.start() > pos:
            runs.append((text[pos:m.start()], style))
        code = m.group(1) or "0"
        if code == "0":
            style = "#c9d1d9"
        else:
            style = STYLES.get(code, STYLES.get(code.split(";")[-1], style))
        pos = m.end()
    if pos < len(text):
        runs.append((text[pos:], style))
    return runs


def load_cast(path):
    """-> (title, [(abs_offset_seconds, runs)])."""
    lines = open(path).read().splitlines()
    header = json.loads(lines[0])
    out, buf = [], ""
    for raw in lines[1:]:
        ev = json.loads(raw)
        if ev[1] != "o":
            continue
        buf += ev[2]
        while "\r\n" in buf or "\n" in buf:
            sep = "\r\n" if "\r\n" in buf else "\n"
            idx = buf.index(sep)
            chunk, buf = buf[:idx], buf[idx + len(sep):]
            out.append((ev[0], parse_ansi(chunk)))
    if buf.strip():
        out.append((float(lines[-1] and json.loads(lines[-1])[0]), parse_ansi(buf)))
    return header.get("title", os.path.basename(path)), out


def wrap(runs, width=COLS):
    """Hard-wrap long lines, carrying the style of the first run."""
    plain = "".join(t for t, _ in runs)
    if len(plain) <= width:
        return [runs]
    chunks, start = [], 0
    while start < len(plain):
        piece = plain[start:start + width]
        colour = runs[0][1]
        chunks.append([(piece, colour)])
        start += width
    return chunks


def esc(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def svg_frame(title, caption, lines):
    parts = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d">' % (W, H),
        '<rect width="100%%" height="100%%" fill="#0b0f14"/>',
        '<rect x="0" y="0" width="%d" height="46" fill="#151b23"/>' % W,
        '<circle cx="22" cy="23" r="6" fill="#ff5f56"/>',
        '<circle cx="44" cy="23" r="6" fill="#ffbd2e"/>',
        '<circle cx="66" cy="23" r="6" fill="#27c93f"/>',
        '<text x="90" y="28" font-family="Menlo,DejaVu Sans Mono,monospace" '
        'font-size="13" fill="#8b98a5">SEALED · Baochip Dabao · USB-C serial · headless</text>',
        '<text x="%d" y="28" text-anchor="end" font-family="Menlo,DejaVu Sans Mono,monospace" '
        'font-size="13" fill="#7ee787">REC</text>' % (W - 20),
    ]
    if caption:
        parts.append(
            '<text x="%d" y="%d" font-family="Menlo,DejaVu Sans Mono,monospace" font-size="17" '
            'fill="#e6edf3">%s</text>' % (LEFT, 46 + 26, esc(caption)))
        y0 = TOP + 26
    else:
        y0 = TOP

    for i, runs in enumerate(lines):
        y = y0 + i * LINE_H
        spans = "".join(
            '<tspan fill="%s">%s</tspan>' % (c, esc(t)) for t, c in runs if t)
        parts.append(
            '<text x="%d" y="%.1f" font-family="Menlo,DejaVu Sans Mono,monospace" '
            'font-size="%.1f" xml:space="preserve">%s</text>' % (LEFT, y, FS, spans))
    parts.append("</svg>")
    return "\n".join(parts)


def build(items, fps):
    """items: [("card", title, caption, dur) | ("cast", (title, events))]"""
    timeline, t = [], 0.0
    for kind, *rest in items:
        if kind == "card":
            title, caption, dur = rest
            timeline.append(("card", t, t + dur, caption))
            t += dur
        else:
            title, events = rest[0]
            timeline.append(("cast", t, t + events[-1][0] + 1.0, events))
            t += events[-1][0] + 1.0
    return timeline, t


def main():
    argv = sys.argv[1:]
    out = "media/demo"
    fps = 8
    shots = []
    items = []
    while argv:
        a = argv.pop(0)
        if a == "--out":
            out = argv.pop(0)
        elif a == "--fps":
            fps = int(argv.pop(0))
        elif a == "--shot":
            shots.append(argv.pop(0))
        elif a == "--card":
            card = argv.pop(0).split("|")
            items.append(("card", card[0], card[1] if len(card) > 1 else "",
                          float(card[2]) if len(card) > 2 else 3.0))
        else:
            items.append(("cast", load_cast(a)))

    timeline, total = build(items, fps)
    frames_dir = out + "-frames"
    shutil.rmtree(frames_dir, ignore_errors=True)
    os.makedirs(frames_dir, exist_ok=True)

    n = int(total * fps)
    stills, idx = [], 0
    for f in range(n):
        now = f / fps
        kind, start, end, payload = timeline[-1]
        for kind, start, end, payload in timeline:
            if start <= now < end:
                break
        if kind == "card":
            lines = []
            cap = payload
        else:
            cap = ""
            visible = [ln for ln in payload if ln[0] <= now - start]
            lines = []
            for _, runs in visible:
                lines.extend(wrap(runs))
            lines = lines[-MAX_LINES:]
        path = os.path.join(frames_dir, "f%05d.svg" % f)
        open(path, "w").write(svg_frame("", cap, lines))
        idx += 1
        # a still per segment, taken mid-way through it
        if abs(now - (start + (end - start) * 0.72)) < 0.5 / fps:
            stills.append((f, start))

    # ImageMagick's built-in SVG renderer ignores font-family, so the font has to
    # be passed explicitly; one conversion per frame, since batch in/out patterns
    # are fragile for SVG.
    font = "/System/Library/Fonts/Menlo.ttc"
    for i in range(idx):
        subprocess.run(["magick", "-font", font, "-density", "96",
                        "%s/f%05d.svg" % (frames_dir, i),
                        "%s/p%05d.png" % (frames_dir, i)], check=True)

    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-framerate", str(fps),
                    "-i", frames_dir + "/p%05d.png", "-c:v", "libx264", "-crf", "20",
                    "-pix_fmt", "yuv420p", "-movflags", "+faststart", out + ".mp4"], check=True)
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", out + ".mp4",
                    "-vf", "fps=10,scale=940:-1:flags=lanczos,split[a][b];"
                           "[a]palettegen=max_colors=128[p];[b][p]paletteuse=dither=bayer",
                    out + ".gif"], check=True)

    for i, (f, start) in enumerate(stills):
        dst = "%s-%02d.png" % (out, i + 1)
        shutil.copyfile("%s/p%05d.png" % (frames_dir, f), dst)
        print("STILL=%s (t=%.1fs)" % (dst, f / fps))

    # Named stills: the frame at which a marker line becomes visible, so a
    # screenshot always shows the state it is named after.
    flat = []  # (global_time, text)
    for kind, start, end, payload in timeline:
        if kind == "cast":
            for t, runs in payload:
                flat.append((start + t, "".join(x for x, _ in runs)))
    for spec in shots:
        marker, _, name = spec.partition("=")
        hit = next((t for t, text in flat if marker in text), None)
        if hit is None:
            print("SHOT_MISS=%s" % marker)
            continue
        f = min(int((hit + 0.55) * fps), idx - 1)
        dst = "%s/shot-%s.png" % (os.path.dirname(out), name)
        shutil.copyfile("%s/p%05d.png" % (frames_dir, f), dst)
        print("SHOT=%s <- %r at t=%.1fs" % (dst, marker, hit))

    print("FRAMES=%d DURATION=%.1fs MP4=%s GIF=%s" %
          (idx, total, out + ".mp4", out + ".gif"))


if __name__ == "__main__":
    main()
