#!/usr/bin/env python3
"""Record a scripted, real demo session to an asciicast v2 file.

Every line in the plan is executed by a real shell against the real board; the
cast only stores what actually came back, plus when. Nothing here is typed by
hand, which is the point: the video is a recording of commands running, not a
re-enactment.

Usage:
    record_demo.py <plan-file> <out.cast> [--title TEXT]

Plan file format (one action per line):
    # comment / blank  -> ignored
    ! shell command    -> echoed as a comment line, not executed
    : pause SECONDS    -> idle time in the recording
    anything else      -> run through /bin/sh, echo "$ cmd" then its output
"""
import json
import os
import subprocess
import sys
import time

COLS, ROWS = 104, 30


def main():
    plan_path, out_path = sys.argv[1], sys.argv[2]
    title = ""
    if "--title" in sys.argv:
        title = sys.argv[sys.argv.index("--title") + 1]

    events = []
    t0 = time.time()

    def emit(text, stamp=None):
        events.append([round((stamp or time.time()) - t0, 3), "o", text])

    if title:
        emit("%s\n" % title, t0)

    for raw in open(plan_path):
        line = raw.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.startswith("!"):
            emit("\x1b[2m%s\x1b[0m\r\n" % line[1:].strip())
            time.sleep(0.35)
            continue
        if line.startswith(": pause"):
            time.sleep(float(line.split()[-1]))
            continue

        emit("\x1b[1;32m$\x1b[0m %s\r\n" % os.path.expandvars(line))
        started = time.time()
        p = subprocess.run(line, shell=True, capture_output=True, text=True)
        stamp = started
        body = (p.stdout or "") + (p.stderr or "")
        for out_line in (body.rstrip("\n").split("\n") if body.strip() else []):
            emit(out_line + "\r\n", stamp)
            stamp += 0.055
        if p.returncode:
            emit("\x1b[31m[exit %d]\x1b[0m\r\n" % p.returncode, stamp)
        time.sleep(0.45)

    header = {
        "version": 2,
        "width": COLS,
        "height": ROWS,
        "timestamp": int(t0),
        "env": {"SHELL": "/bin/sh", "TERM": "xterm-256color"},
        "title": title or "SEALED demo",
    }
    with open(out_path, "w") as f:
        f.write(json.dumps(header) + "\n")
        for ev in events:
            f.write(json.dumps(ev) + "\n")
    dur = events[-1][0] if events else 0
    print("WROTE=%s events=%d duration=%.1fs" % (out_path, len(events), dur))


if __name__ == "__main__":
    main()
