"""skillsplit stage 1: static rule scanner.

Reads data/manifest.csv, scans each skill folder with the regex rules in rules.yaml
(and optionally the tree-sitter shell detector in ast_shell.py), writes predictions.csv
in the format fixed by docs/data-format.md.

    python -m skillsplit.stage1.scan --manifest data/manifest.csv \
        --rules skillsplit/stage1/rules.yaml --out runs/stage1_v0.csv \
        [--limit N] [--skill-md-only] [--use-ast] [--raw-root data/raw]

Score (first guess, to be tuned on the dev split only):
    max severity of hit rules  {NONE 0, LOW .25, MEDIUM .5, HIGH .75, CRITICAL 1.0}
    + 0.05 per additional distinct family hit, capped at 1.0
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

import yaml

SEV = {"NONE": 0.0, "LOW": 0.25, "MEDIUM": 0.5, "HIGH": 0.75, "CRITICAL": 1.0}
EXT = {".sh": "shell", ".bash": "shell", ".zsh": "shell", ".py": "python",
       ".js": "js", ".ts": "js", ".mjs": "js", ".md": "markdown",
       ".txt": "other", ".json": "other", ".yaml": "other", ".yml": "other"}
MAX_BYTES = 2 * 1024 * 1024
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}
MAX_HITS_PER_RULE_FILE = 3
AST_RULE = {"id": "AST_DL_PIPE_SH", "family": "remote_install", "severity": "CRITICAL"}
COLUMNS = ["skill_id", "score", "verdict", "evidence", "error"]


def load_rules(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        doc = yaml.safe_load(f)
    rules = []
    for r in doc["rules"]:
        flags = re.MULTILINE | (0 if r.get("case_sensitive") else re.IGNORECASE)
        r["rx"] = re.compile(r["regex"], flags)
        r["author"] = (r.get("source") or {}).get("author")
        rules.append(r)
    return rules


def file_type(p: Path) -> str | None:
    if p.name.lower() == "skill.md":
        return "markdown"
    return EXT.get(p.suffix.lower())


def iter_files(root: Path, skill_md_only: bool):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            p = Path(dirpath) / name
            if skill_md_only and name.lower() != "skill.md":
                continue
            if file_type(p) is not None:
                yield p


def snippet_at(text: str, pos: int) -> tuple[int, str]:
    line = text.count("\n", 0, pos) + 1
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    return line, text[start:end if end != -1 else len(text)].strip()[:80]


def scan_text(text: str, ftype: str, rules: list[dict], relname: str) -> list[dict]:
    hits = []
    for r in rules:
        fts = r["file_types"]
        if "any" not in fts and ftype not in fts:
            continue
        for n, m in enumerate(r["rx"].finditer(text)):
            if n >= MAX_HITS_PER_RULE_FILE:
                break
            line, snip = snippet_at(text, m.start())
            ev = {"rule_id": r["id"], "file": relname, "line": line, "snippet": snip}
            if r["author"]:  # DRL 1.1: keep the Sigma author in the finding
                ev["author"] = r["author"]
            hits.append(ev)
    return hits


def scan_ast(text: str, ftype: str, relname: str, ast_mod) -> list[dict]:
    if ftype == "shell":
        blocks = [(0, text)]
    elif ftype == "markdown":
        blocks = ast_mod.fenced_shell_blocks(text)
    else:
        return []
    out = []
    for offset, code in blocks:
        for h in ast_mod.pipeline_download_to_shell(code, line_offset=offset):
            out.append({"rule_id": AST_RULE["id"], "file": relname,
                        "line": h["line"], "snippet": h["snippet"][:80]})
    return out


def scan_skill(skill_dir: Path, rules: list[dict], skill_md_only: bool, ast_mod) -> list[dict]:
    evidence = []
    for p in iter_files(skill_dir, skill_md_only):
        rel = p.relative_to(skill_dir).as_posix()
        if p.stat().st_size > MAX_BYTES:
            evidence.append({"rule_id": "oversize", "file": rel, "line": 0,
                             "snippet": f"{p.stat().st_size} bytes > {MAX_BYTES}"})
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        ftype = file_type(p)
        evidence += scan_text(text, ftype, rules, rel)
        if ast_mod is not None:
            evidence += scan_ast(text, ftype, rel, ast_mod)
    return evidence


def score_of(evidence: list[dict], rules_by_id: dict) -> float:
    sevs, families = [], set()
    for ev in evidence:
        r = rules_by_id.get(ev["rule_id"])
        if r is None:  # "oversize" carries no severity
            continue
        sevs.append(SEV[r["severity"]])
        families.add(r["family"])
    if not sevs:
        return 0.0
    return round(min(1.0, max(sevs) + 0.05 * (len(families) - 1)), 4)


def verdict_of(score: float) -> str:
    return "MALICIOUS" if score >= 0.75 else "SUSPICIOUS" if score >= 0.5 else "SAFE"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--rules", default="skillsplit/stage1/rules.yaml")
    ap.add_argument("--out", required=True)
    ap.add_argument("--raw-root", default="data/raw", help="manifest `path` is relative to this")
    ap.add_argument("--limit", type=int, default=0, help="scan only the first N manifest rows")
    ap.add_argument("--skill-md-only", action="store_true")
    ap.add_argument("--use-ast", action="store_true", help="also run tree-sitter shell detector")
    args = ap.parse_args(argv)

    ast_mod = None
    if args.use_ast:
        from . import ast_shell
        if not ast_shell.AVAILABLE:
            sys.exit("--use-ast needs tree-sitter: " + ast_shell.INSTALL)
        ast_mod = ast_shell

    rules = load_rules(args.rules)
    rules_by_id = {r["id"]: r for r in rules}
    rules_by_id[AST_RULE["id"]] = AST_RULE
    raw_root = Path(args.raw_root)

    with open(args.manifest, encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    if args.limit:
        rows = rows[: args.limit]

    results, rule_counter, n_hit = [], Counter(), 0
    for row in rows:
        rec = {"skill_id": row["skill_id"], "score": 0.0, "verdict": "", "evidence": "[]", "error": ""}
        if not row.get("path"):
            rec["error"] = "no_path"
        elif not (raw_root / row["path"]).is_dir():
            rec["error"] = "path_not_found"
        else:
            try:
                ev = scan_skill(raw_root / row["path"], rules, args.skill_md_only, ast_mod)
                rec["score"] = score_of(ev, rules_by_id)
                rec["verdict"] = verdict_of(rec["score"])
                rec["evidence"] = json.dumps(ev, ensure_ascii=False)
                if ev:
                    n_hit += 1
                    rule_counter.update({e["rule_id"] for e in ev})
            except Exception as exc:  # keep the row; the contract wants a score for every skill
                rec["error"] = f"scan_failed: {type(exc).__name__}: {exc}"[:200]
        results.append(rec)

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(results)

    print(f"rows scanned: {len(results)}  rows with hits: {n_hit}  "
          f"errors: {sum(1 for r in results if r['error'])}  -> {args.out}")
    print("top rules (number of skills hit):")
    for rid, c in rule_counter.most_common(10):
        print(f"  {c:5d}  {rid}")
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:
        pass
    sys.exit(main())
