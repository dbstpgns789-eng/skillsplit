"""Record how many files each skill SHOULD have, straight from the downloaded archives.

Why: real malicious samples get quarantined by antivirus after extraction, so the
on-disk file count can silently drop. build_manifest.py compares against this index
and marks rows whose files are missing (`intact=0`).

Usage: python data/index_archives.py --malskillbench <MalSkillBench tarball> \
         --skilltrustbench <benchmark_full_v1.0.zip> --msb-packages <dir with SRC*_*.tar.gz>
Writes data/raw/_expected_files.json  {skill_id: n_files}
"""
import argparse, json, os, re, tarfile, zipfile
from collections import Counter

WIN_BAD = re.compile(r'[:*?"<>|]')


def safe(seg):
    return WIN_BAD.sub("_", seg)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--malskillbench")
    ap.add_argument("--skilltrustbench")
    ap.add_argument("--msb-packages")
    a = ap.parse_args()
    exp = Counter()

    if a.malskillbench:
        with tarfile.open(a.malskillbench) as t:
            for m in t:
                if not m.isfile():
                    continue
                parts = m.name.split("/")[1:]          # drop "MalSkillBench-main/"
                if len(parts) >= 4 and parts[:2] == ["Dataset", "Skills"] and parts[2] in ("malware", "benign"):
                    exp["msb:" + safe(parts[3])] += 1

    if a.skilltrustbench:
        with zipfile.ZipFile(a.skilltrustbench) as z:
            for n in z.namelist():
                if n.endswith("/"):
                    continue
                parts = n.split("/")
                if len(parts) >= 3 and parts[1].startswith("case_"):
                    exp["stb:" + parts[1]] += 1

    if a.msb_packages:
        for f in sorted(os.listdir(a.msb_packages)):
            if not f.endswith(".tar.gz"):
                continue
            with tarfile.open(os.path.join(a.msb_packages, f)) as t:
                for m in t:
                    if not m.isfile():
                        continue
                    parts = m.name.split("/")
                    if len(parts) >= 2 and "_" in parts[1]:
                        exp["asb:" + parts[1].split("_", 1)[1]] += 1

    out = os.path.join(os.path.dirname(__file__), "raw", "_expected_files.json")
    json.dump(dict(exp), open(out, "w", encoding="utf-8"), ensure_ascii=False)
    print(f"{len(exp)} skills indexed -> {out}")


if __name__ == "__main__":
    main()
