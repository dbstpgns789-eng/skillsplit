"""Build data/manifest.csv from the three raw benchmarks (see docs/data-format.md).

Raw layout expected under data/raw/ (never committed):
  MalSkillBench/Dataset/Skills/{malware,benign}/<name>/...   + malware/_source_inventory.txt
  SkillTrustBench/benchmark_full_v1.0/case_XXXXX/...          + ground_truth.json
  MaliciousSkillBench/text/<benchmark_id>/SKILL.md            (from HF `primary`)
  MaliciousSkillBench/packages/SRCxxx/packages/<n>_<id>/...   (malicious only)
  MaliciousSkillBench/metadata/benchmark_manifest.csv         (frozen splits)

Usage: python data/build_manifest.py [--seed 42] [--dev-frac 0.3]
Writes data/manifest.csv and data/manifest.sha256.
"""
import argparse, csv, hashlib, json, os, random, re
from collections import defaultdict

RAW = os.path.join(os.path.dirname(__file__), "raw")
WIN_BAD = re.compile(r'[:*?"<>|]')
SCRIPT_EXT = {".py", ".sh", ".bash", ".zsh", ".js", ".ts", ".mjs"}
COLS = ["skill_id", "dataset", "path", "label", "label3", "origin", "origin_group", "vector",
        "taxonomy", "split", "n_files", "files_expected", "intact", "has_script", "skill_md_chars"]


def dir_stats(path):
    n, script, md_chars = 0, 0, 0
    if not path or not os.path.isdir(path):
        return 0, 0, 0
    for root, _, files in os.walk(path):
        for f in files:
            n += 1
            if os.path.splitext(f)[1].lower() in SCRIPT_EXT:
                script = 1
            if f.lower() == "skill.md" and root == path:
                md_chars = os.path.getsize(os.path.join(root, f))
    return n, script, md_chars


def rel(p):
    return os.path.relpath(p, RAW).replace("\\", "/")


def skill_dir(root):
    """Shallowest directory under root that holds a SKILL.md (case-insensitive), else root."""
    best = None
    for dp, _, fs in os.walk(root):
        if any(f.lower() == "skill.md" for f in fs) and (best is None or dp.count(os.sep) < best.count(os.sep)):
            best = dp
    return best or root


# ---------- MalSkillBench ----------
def malskillbench():
    base = os.path.join(RAW, "MalSkillBench", "Dataset", "Skills")
    inv_path = os.path.join(base, "malware", "_source_inventory.txt")
    # Origin lines:  "GENERATED  <name>  <-  <source-path>"  (also WILD / TEST)
    # Label lines:   "GENERATED_LABEL  <Vector>  <Bxx>  <Behavior>  <Strategy>  <name>  <-  <source-path>"
    # Names may contain spaces, so join origin and label lines on the source path.
    origin, path_of, label_of = {}, {}, {}
    if os.path.exists(inv_path):
        for line in open(inv_path, encoding="utf-8", errors="ignore"):
            if "<-" not in line or line.startswith("#"):
                continue
            left, src = [x.strip() for x in line.split("<-", 1)]
            src = src.split("  #")[0].split(",")[0].strip()   # drop rationale / extra paths
            tag, rest = left.split(None, 1)
            if tag in ("GENERATED", "WILD", "TEST"):
                name = WIN_BAD.sub("_", rest.strip())          # dirs were extracted with ':' -> '_'
                origin[name] = tag.lower()
                path_of[name] = src
            elif tag.endswith("_LABEL"):
                m = re.match(r"(?:(CI|PI|MIXED)\s+)?(B\d+)\s+(.*)", rest)
                if m:
                    label_of[src] = (m.group(1) or "", m.group(2), m.group(3).strip())
    taxo = {name: label_of.get(p, ("", "", "")) for name, p in path_of.items()}
    rows = []
    for label, sub in ((1, "malware"), (0, "benign")):
        d = os.path.join(base, sub)
        if not os.path.isdir(d):
            continue
        for name in sorted(os.listdir(d)):
            p = os.path.join(d, name)
            if not os.path.isdir(p) or name.startswith("_"):
                continue
            p = skill_dir(p)
            n, sc, mdc = dir_stats(p)
            if label == 1:
                og = origin.get(name, "unknown")
                vec, beh, rest = taxo.get(name, ("", "", ""))
                tx = json.dumps({"behavior": beh, "detail": rest}, ensure_ascii=False) if beh else ""
                grp = "real" if og in ("wild", "test") else ("synthetic" if og == "generated" else "unknown")
            else:
                og, vec, tx, grp = "benign_top_downloaded", "", "", "real"
            rows.append(dict(skill_id=f"msb:{name}", dataset="malskillbench", path=rel(p), label=label,
                             label3="", origin=og, origin_group=grp, vector=vec,
                             taxonomy=tx,
                             n_files=n, has_script=sc, skill_md_chars=mdc))
    return rows


# ---------- SkillTrustBench ----------
def skilltrustbench():
    base = os.path.join(RAW, "SkillTrustBench", "benchmark_full_v1.0")
    gt = os.path.join(base, "ground_truth.json")
    if not os.path.exists(gt):
        return []
    g = json.load(open(gt, encoding="utf-8"))
    rows = []
    for c in g["test_cases"]:
        p = skill_dir(os.path.join(RAW, "SkillTrustBench", c["skill_path"]))
        n, sc, mdc = dir_stats(p)
        src = c.get("source", "")
        # safe_pool = benign seed skills taken from marketplaces (treated as real; origin kept for filtering)
        grp = "real" if src.startswith(("wild", "external", "safe_pool")) else "synthetic"
        rows.append(dict(skill_id=f"stb:{c['id']}", dataset="skilltrustbench", path=rel(p),
                         label=1 if c["judgment"] == "malicious" else 0, label3=c["judgment"],
                         origin=src, origin_group=grp, vector="",
                         taxonomy=json.dumps({k: c.get(k) for k in ("risk_labels", "attack_pattern",
                                              "primary_pattern", "base_category", "trigger_type", "encoding")},
                                             ensure_ascii=False),
                         n_files=n, has_script=sc, skill_md_chars=mdc))
    return rows


# ---------- MaliciousSkillBench ----------
def maliciousskillbench():
    base = os.path.join(RAW, "MaliciousSkillBench")
    meta = os.path.join(base, "metadata", "benchmark_manifest.csv")
    if not os.path.exists(meta):
        return []
    pkg = {}
    pm = os.path.join(base, "packages")
    for src in os.listdir(pm) if os.path.isdir(pm) else []:
        for sub in ("packages", "artifacts"):
            d = os.path.join(pm, src, sub)
            if os.path.isdir(d):
                for name in os.listdir(d):
                    bid = name.split("_", 1)[1] if "_" in name else name
                    pkg[bid] = os.path.join(d, name)
    grp_map = {"wild": "real", "mixed_unresolved": "unknown"}
    rows = []
    for r in csv.DictReader(open(meta, encoding="utf-8")):
        bid = r["benchmark_id"]
        # package dir if it contains a SKILL.md (possibly nested); otherwise the HF text copy
        p = skill_dir(pkg[bid]) if bid in pkg else None
        if p is None or not any(f.lower() == "skill.md" for f in os.listdir(p)):
            p = os.path.join(base, "text", bid)
        n, sc, mdc = dir_stats(p)
        rows.append(dict(skill_id=f"asb:{bid}", dataset="maliciousskillbench", path=rel(p),
                         label=int(r["label"]), label3="", origin=r["provenance"],
                         origin_group=grp_map.get(r["provenance"], "synthetic"), vector="",
                         taxonomy=json.dumps({"attack_categories": r["attack_categories"],
                                              "evidence_type": r["evidence_type"], "source_id": r["source_id"],
                                              "source_disjoint": r["source_disjoint_split"],
                                              "random": r["random_split"],
                                              "text_only": os.path.basename(os.path.dirname(p)) == "text"},
                                             ensure_ascii=False),
                         n_files=n, has_script=sc, skill_md_chars=mdc))
    return rows


def assign_split(rows, seed, dev_frac):
    rnd = random.Random(seed)
    groups = defaultdict(list)
    for r in rows:
        groups[(r["dataset"], r["label"], r["origin_group"])].append(r)
    for key, g in groups.items():
        # split is decided from the ARCHIVE (files_expected), never from this machine's disk state,
        # so every team member gets the same dev/test partition. Quarantined files only affect `intact`.
        g = [r for r in g if (r["files_expected"] or r["n_files"]) and (r["files_expected"] or 0) != 0]
        g.sort(key=lambda r: r["skill_id"])
        rnd.shuffle(g)
        k = round(len(g) * dev_frac)
        for i, r in enumerate(g):
            r["split"] = "dev" if i < k else "test"
    for r in rows:
        r.setdefault("split", "unavailable")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--dev-frac", type=float, default=0.3)
    a = ap.parse_args()
    rows = malskillbench() + skilltrustbench() + maliciousskillbench()
    exp_path = os.path.join(RAW, "_expected_files.json")
    expected = json.load(open(exp_path, encoding="utf-8")) if os.path.exists(exp_path) else {}
    for r in rows:
        e = expected.get(r["skill_id"])
        if e is None and r["dataset"] == "maliciousskillbench":
            e = 1 if "text_only" in r["taxonomy"] and '"text_only": true' in r["taxonomy"] else None
        r["files_expected"] = e if e is not None else ""
        # intact = every expected file is present on disk (antivirus may have quarantined some)
        r["intact"] = "" if e is None else int(r["n_files"] >= e)
    assign_split(rows, a.seed, a.dev_frac)
    out = os.path.join(os.path.dirname(__file__), "manifest.csv")
    with open(out, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLS)
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in COLS})
    h = hashlib.sha256(open(out, "rb").read()).hexdigest()
    open(out.replace(".csv", ".sha256"), "w").write(h + "  manifest.csv\n")
    summ = defaultdict(int)
    for r in rows:
        summ[(r["dataset"], r["label"], r["origin_group"], r["split"])] += 1
    print(f"rows={len(rows)} sha256={h[:12]}")
    for k in sorted(summ):
        print(*k, summ[k])


if __name__ == "__main__":
    main()
