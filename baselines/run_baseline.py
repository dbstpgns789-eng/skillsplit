"""Run one public skill scanner over data/manifest.csv and write predictions.csv.

Contract: docs/data-format.md (predictions.csv) and docs/baselines.md (score mapping, gates).
Stdlib only; the scanner itself must be installed elsewhere and is called via subprocess.

  python baselines/run_baseline.py --tool cisco --manifest data/manifest.csv \
      --exe <venv>/Scripts/skill-scanner.exe [--out runs/baseline_cisco_YYYYMMDD.csv] \
      [--limit N] [--skill-md-only] [--batch 200] [--timeout 3600]

--exe    path to the tool CLI (cisco: skill-scanner, skillspector, skillfortify) or, for
         skillgate, the python.exe of the venv where skillgate is installed. Default: on PATH.
--skill-md-only  copy only SKILL.md (MaliciousSkillBench-comparable single-artifact condition).

Score mapping (all in [0,1], larger = more malicious):
  cisco        max_severity  NONE/INFO 0, LOW .25, MEDIUM .5, HIGH .75, CRITICAL 1   verdict: is_safe -> SAFE/UNSAFE
  skillspector risk_assessment.score / 100; batch capped at 32 (tool budget)        verdict: recommendation
  skillfortify max_severity, same map (null -> 0); always 1 skill per call          verdict: is_safe -> SAFE/UNSAFE
  skillgate    prefilter hit -> 0.5 (its fixed MEDIUM), no hit -> 0                  verdict: severity or SAFE
Failures never become benign: score 0.0 + error="ABSTAIN_ERROR:<reason>".
"""
import argparse, csv, datetime, json, os, platform, shutil, subprocess, sys, tempfile, time

SEV = {"NONE": 0.0, "INFO": 0.0, "LOW": 0.25, "MEDIUM": 0.5, "HIGH": 0.75, "CRITICAL": 1.0}
PKG = {"cisco": "cisco-ai-skill-scanner", "skillspector": "skillspector",
       "skillfortify": "skillfortify", "skillgate": "skillgate"}
DEFAULT_EXE = {"cisco": "skill-scanner", "skillspector": "skillspector",
               "skillfortify": "skillfortify", "skillgate": "python"}
COLS = ["skill_id", "score", "verdict", "evidence", "error"]

# SkillGate has no JSON CLI; this snippet runs inside its venv and prints one JSON list.
SKILLGATE_SNIPPET = r"""
import asyncio, json, os, sys
from pathlib import Path
from skillgate.classifier.hybrid import create_classifier
from skillgate.interceptor.response import ScanContext
clf = create_classifier(use_llm=False)
out = []
for n in sorted(os.listdir(sys.argv[1])):
    p = os.path.join(sys.argv[1], n, "SKILL.md")
    try:
        t = Path(p).read_text(encoding="utf-8", errors="replace")
        r = asyncio.run(clf.classify(t, ScanContext(tool_name="scan", upstream="local", source_path=p)))
        out.append({"name": n, "severity": r.severity.name if r.severity else None,
                    "rules": [m.rule.id for m in r.rule_matches], "warnings": list(r.warnings)})
    except Exception as e:
        out.append({"name": n, "error": type(e).__name__ + ":" + str(e)[:120]})
print(json.dumps(out))
"""


def safe_name(skill_id):
    return skill_id.replace(":", "__").replace("/", "_").replace("\\", "_")


def top_ids(seq, k=5):
    seen = []
    for x in seq:
        if x and x not in seen:
            seen.append(x)
    return json.dumps(seen[:k])


def build_cmd(tool, exe, root):
    if tool == "cisco":
        return [exe, "scan-all", root, "--use-behavioral", "--format", "json"]
    if tool == "skillspector":
        return [exe, "scan", root, "--recursive", "--no-llm", "--format", "json"]
    if tool == "skillfortify":
        return [exe, "scan", root, "--format", "json"]
    return [exe, "-c", SKILLGATE_SNIPPET, root]


def parse(tool, data):
    """Return {dir_name: (score, verdict, evidence, error)} from the tool's JSON."""
    res = {}
    if tool == "cisco":
        for r in data.get("results", []):
            fs = sorted(r.get("findings", []), key=lambda f: -SEV.get(f.get("severity", ""), 0))
            res[os.path.basename(r["skill_path"])] = (
                SEV.get(r.get("max_severity") or "NONE", 0.0), "SAFE" if r.get("is_safe") else "UNSAFE",
                top_ids(f.get("rule_id") for f in fs if f.get("severity") != "INFO"), "")
    elif tool == "skillspector":
        for s in data.get("skills", [data]):
            if "skill" not in s:  # e.g. {"omitted": true, "reason": "aggregate_scan_limit"} past the 32-skill budget
                continue
            ra = s.get("risk_assessment", {})
            res[os.path.basename(s["skill"]["source"])] = (
                min(1.0, ra.get("score", 0) / 100.0), ra.get("recommendation", ""),
                top_ids(i.get("id") for i in s.get("issues", [])), "")
    elif tool == "skillfortify":
        for r in data if isinstance(data, list) else data.get("skills", []):
            res[r["skill_name"]] = (
                SEV.get(r.get("max_severity") or "NONE", 0.0), "SAFE" if r.get("is_safe") else "UNSAFE",
                top_ids(f"{f.get('attack_class')}:{f.get('attack_type')}" for f in r.get("findings", [])), "")
    else:
        for r in data:
            if r.get("error"):
                res[r["name"]] = (0.0, "", "", "ABSTAIN_ERROR:" + r["error"])
            else:
                res[r["name"]] = (0.5 if r.get("severity") else 0.0, r.get("severity") or "SAFE",
                                  top_ids(r.get("rules") or r.get("warnings") or []), "")
    return res


def materialize(rows, raw_dir, root, tool, md_only):
    """Copy skills into the layout the tool expects. Returns (dir_name -> skill_id, pre-errors)."""
    base = os.path.join(root, "skills") if tool == "skillfortify" else root
    os.makedirs(base, exist_ok=True)
    names, errors = {}, {}
    for row in rows:
        src = os.path.join(raw_dir, row["path"])
        md = os.path.join(src, "SKILL.md")
        if not os.path.isdir(src):
            errors[row["skill_id"]] = "ABSTAIN_ERROR:path_missing"
            continue
        if md_only and not os.path.isfile(md):
            errors[row["skill_id"]] = "ABSTAIN_ERROR:no_skill_md"
            continue
        dst = os.path.join(base, safe_name(row["skill_id"]))
        if md_only:
            os.makedirs(dst)
            shutil.copy2(md, dst)
        else:
            shutil.copytree(src, dst)
        names[os.path.basename(dst)] = row["skill_id"]
    return names, errors


def run_batch(tool, exe, rows, raw_dir, md_only, timeout, raw_path):
    """Scan one batch. Returns ({skill_id: (score, verdict, evidence, error)}, batch meta)."""
    tmp = tempfile.mkdtemp(prefix="skillsplit_")
    out, meta = {}, {"n": len(rows)}
    try:
        names, errors = materialize(rows, raw_dir, tmp, tool, md_only)
        for sid, err in errors.items():
            out[sid] = (0.0, "", "", err)
        cmd = build_cmd(tool, exe, tmp)
        t0 = time.time()
        try:
            p = subprocess.run(cmd, capture_output=True, timeout=timeout)
            stdout, stderr, rc = p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace"), p.returncode
        except subprocess.TimeoutExpired:
            stdout, stderr, rc = "", "timeout", -1
        except OSError as e:
            stdout, stderr, rc = "", str(e), -2
        meta.update(seconds=round(time.time() - t0, 2), returncode=rc, cmd=cmd[:2] + ["<snippet>" if tool == "skillgate" else cmd[2]] + cmd[3:])
        with open(raw_path + ".json", "w", encoding="utf-8") as f:
            f.write(stdout)
        with open(raw_path + ".err", "w", encoding="utf-8") as f:
            f.write(stderr)
        try:
            parsed = parse(tool, json.loads(stdout))
            reason = "ABSTAIN_ERROR:no_result"
            if tool == "skillfortify" and len(parsed) == 1 and len(names) == 1:  # JSON has no path; batch is 1
                parsed = {next(iter(names)): next(iter(parsed.values()))}
        except (ValueError, KeyError, TypeError) as e:
            parsed = {}
            reason = "ABSTAIN_ERROR:tool_failed:" + ("timeout" if rc == -1 else f"rc={rc}:{type(e).__name__}")
        for dname, sid in names.items():
            out[sid] = parsed.get(dname, (0.0, "", "", reason))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return out, meta


def tool_version(exe, pkg):
    exe_path = shutil.which(exe) or exe
    d = os.path.dirname(exe_path)
    py = next((p for p in (os.path.join(d, "python.exe"), os.path.join(d, "python")) if os.path.isfile(p)), exe_path)
    try:
        txt = subprocess.run([py, "-m", "pip", "show", pkg], capture_output=True, timeout=120).stdout.decode("utf-8", "replace")
        return next((l.split(":", 1)[1].strip() for l in txt.splitlines() if l.startswith("Version:")), "unknown")
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tool", required=True, choices=list(PKG))
    ap.add_argument("--manifest", default="data/manifest.csv")
    ap.add_argument("--out", help="default runs/baseline_<tool>_<YYYYMMDD>.csv")
    ap.add_argument("--exe", help="tool CLI path (skillgate: venv python.exe)")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--skill-md-only", action="store_true")
    ap.add_argument("--batch", type=int, default=200)
    ap.add_argument("--timeout", type=int, default=3600, help="seconds per batch")
    a = ap.parse_args()
    if a.tool == "skillfortify":
        a.batch = 1  # its JSON names skills by frontmatter `name`, not directory: one skill per call
    if a.tool == "skillspector":
        a.batch = min(a.batch, 32)  # hard-coded _MULTI_SKILL_MAX_SKILLS = 32 in cli.py; the rest is omitted

    repo =os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    raw_dir = os.path.join(repo, "data", "raw")
    exe = a.exe or DEFAULT_EXE[a.tool]
    date = datetime.date.today().strftime("%Y%m%d")
    out = a.out or os.path.join(repo, "runs", f"baseline_{a.tool}_{date}.csv")
    raw_out = os.path.splitext(out)[0] + ".raw"
    os.makedirs(raw_out, exist_ok=True)

    with open(a.manifest, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    if a.limit:
        rows = rows[:a.limit]
    todo = [r for r in rows if r.get("path")]
    results = {r["skill_id"]: (0.0, "", "", "ABSTAIN_ERROR:no_path") for r in rows if not r.get("path")}

    started = time.time()
    batches = []
    for i in range(0, len(todo), a.batch):
        chunk = todo[i:i + a.batch]
        res, meta = run_batch(a.tool, exe, chunk, raw_dir, a.skill_md_only, a.timeout,
                              os.path.join(raw_out, f"batch_{i // a.batch:04d}"))
        results.update(res)
        meta["index"] = i // a.batch
        batches.append(meta)
        n_err = sum(1 for v in res.values() if v[3])
        print(f"[{a.tool}] batch {meta['index']} n={meta['n']} {meta.get('seconds')}s rc={meta.get('returncode')} errors={n_err}", flush=True)

    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(COLS)
        for r in rows:
            score, verdict, evidence, error = results[r["skill_id"]]
            w.writerow([r["skill_id"], f"{score:.4f}", verdict, evidence, error])

    meta = {"tool": a.tool, "package": PKG[a.tool], "version": tool_version(exe, PKG[a.tool]), "exe": exe,
            "argv": sys.argv, "command_template": build_cmd(a.tool, exe, "<batch_root>")[:2] + ["..."] if a.tool == "skillgate"
            else build_cmd(a.tool, exe, "<batch_root>"),
            "skill_md_only": a.skill_md_only, "manifest": os.path.abspath(a.manifest), "out": os.path.abspath(out),
            "n_rows": len(rows), "n_error": sum(1 for v in results.values() if v[3]),
            "started": datetime.datetime.fromtimestamp(started).isoformat(timespec="seconds"),
            "wall_seconds": round(time.time() - started, 2), "batches": batches,
            "host": {"platform": platform.platform(), "python": platform.python_version()}}
    with open(os.path.splitext(out)[0] + ".meta.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)
    print(f"wrote {out} ({meta['n_rows']} rows, {meta['n_error']} errors, {meta['wall_seconds']}s, {a.tool} {meta['version']})")


if __name__ == "__main__":
    main()
