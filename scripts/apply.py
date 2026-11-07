#!/usr/bin/env python3
"""
apply.py — graft the SEALED command onto a stock xous-core checkout.

    python3 scripts/apply.py --xous ~/code/xous-core          # apply
    python3 scripts/apply.py --xous ~/code/xous-core --revert # undo

Idempotent: running twice changes nothing. Touches exactly three files in the
target tree:

    apps-dabao/dabao-console/src/cmds/sealed.rs   (new file, copied from board/)
    apps-dabao/dabao-console/src/cmds.rs          (4 small insertions)
    apps-dabao/dabao-console/Cargo.toml           (2 dependencies)
"""
import argparse
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, "board", "sealed.rs")

EDITS = [
    ("cmds.rs",
     "mod bio;\nuse bio::*;\n",
     "mod bio;\nuse bio::*;\nmod sealed;\nuse sealed::*;\n"),
    ("cmds.rs",
     "    bio: BioLoader,\n}",
     "    bio: BioLoader,\n    sealed: SealedCmd,\n}"),
    ("cmds.rs",
     "            bio: BioLoader::new(),\n        }",
     "            bio: BioLoader::new(),\n            sealed: SealedCmd::new(&xns),\n        }"),
    ("cmds.rs",
     "            &mut self.bio,\n        ];",
     "            &mut self.bio,\n            &mut self.sealed,\n        ];"),
    ("Cargo.toml",
     'keystore = { path = "../../services/keystore", features = ["board-dabao"] }',
     'keystore = { path = "../../services/keystore", features = ["board-dabao"] }\n'
     'p256 = { version = "0.11.1", default-features = false, features = ["ecdsa", "ecdh", "std"] }\n'
     'sha2 = "0.10"'),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--xous", required=True, help="path to an xous-core checkout")
    ap.add_argument("--revert", action="store_true")
    a = ap.parse_args()

    app = os.path.join(a.xous, "apps-dabao", "dabao-console")
    if not os.path.isdir(app):
        sys.exit("not an xous-core checkout: %s" % a.xous)

    target = os.path.join(app, "src", "cmds", "sealed.rs")

    if a.revert:
        if os.path.exists(target):
            os.unlink(target)
        for name, new, old in [(e[0], e[2], e[1]) for e in EDITS]:
            p = os.path.join(app, "src", name) if name == "cmds.rs" else os.path.join(app, name)
            with open(p) as f:
                t = f.read()
            if new in t:
                t = t.replace(new, old, 1)
                with open(p, "w") as f:
                    f.write(t)
        print("reverted")
        return

    shutil.copyfile(SRC, target)
    print("copied %s -> %s" % (SRC, target))

    for name, old, new in EDITS:
        p = os.path.join(app, "src", name) if name == "cmds.rs" else os.path.join(app, name)
        with open(p) as f:
            t = f.read()
        if new in t:
            print("already applied: %s" % name)
            continue
        if old not in t:
            sys.exit("anchor not found in %s — xous-core drifted, patch manually" % p)
        with open(p, "w") as f:
            f.write(t.replace(old, new, 1))
        print("patched %s" % name)


if __name__ == "__main__":
    main()
