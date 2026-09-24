"""Stage 2 LLM judge: manifest.csv -> predictions.csv (contract: docs/data-format.md).

Usage:
    python -m skillsplit.stage2.judge --manifest data/manifest.csv \
        --prompt skillsplit/stage2/prompts/judge_v1.md --model gpt-5.4-mini \
        --out runs/stage2_v1.csv [--limit N] [--runs 3] [--split dev] [--dry-run] \
        [--base-url URL] [--price-in USD/MTok --price-out USD/MTok]

API key: env OPENAI_API_KEY or SKILLSPLIT_LLM_API_KEY. It is never logged.
The model only sees the system prompt and the (truncated) SKILL.md text;
skill_id, source ids, and labels are never sent.

Score mapping (a v1 choice, see docs/stage2-guide.md section 4):
    MALICIOUS -> confidence | SUSPICIOUS -> 0.5 * confidence | SAFE -> (1 - confidence) * 0.2
"""
import argparse, csv, hashlib, json, os, re, sqlite3, statistics, sys, time  # noqa: E401
from collections import Counter
from pathlib import Path

HEAD, TAIL = 8000, 4000
LABELS = ("MALICIOUS", "SUSPICIOUS", "SAFE")  # severity order, used for tie-breaks
BEGIN, END = "<<<SKILL_MD_BEGIN>>>", "<<<SKILL_MD_END>>>"
FIELDS = ["skill_id", "score", "verdict", "confidence", "evidence", "error"]
DATAMARK_RE = re.compile(r"<!--\s*skillsplit-datamark:\s*(\S)\s*-->")
FENCE_RE = re.compile(r"(```.*?```|~~~.*?~~~)", re.S)


def sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def truncate(text: str) -> tuple[str, int]:
    """Keep head 8,000 + tail 4,000 chars. Returns (text, omitted_chars)."""
    if len(text) <= HEAD + TAIL:
        return text, 0
    omitted = len(text) - HEAD - TAIL
    return text[:HEAD] + f"\n[... {omitted} chars omitted ...]\n" + text[-TAIL:], omitted


def datamark(text: str, mark: str) -> str:
    """Spotlighting datamarking on prose only: frontmatter and code fences untouched."""
    fm = ""
    if text.startswith("---"):
        end = text.find("\n---", 3)
        if end != -1:
            fm, text = text[: end + 4], text[end + 4 :]
    parts = FENCE_RE.split(text)  # even indices = prose, odd = fences
    for i in range(0, len(parts), 2):
        parts[i] = re.sub(r"[ \t]+", mark, parts[i])
    return fm + "".join(parts)


def load_prompt(path: str) -> tuple[str, str | None, str]:
    """Returns (system_prompt, datamark_char_or_None, sha256_of_file)."""
    raw = Path(path).read_text(encoding="utf-8")
    m = DATAMARK_RE.search(raw)
    system = re.sub(r"<!--.*?-->", "", raw, flags=re.S).strip()
    return system, (m.group(1) if m else None), sha(raw)


def parse_response(raw: str) -> tuple[str, float, list, list, str, str]:
    """(label, confidence, categories, evidence, reasoning, error). Fail-closed."""
    try:
        s = raw.strip()
        m = re.search(r"```(?:json)?\s*(.*?)```", s, re.S)
        if m:
            s = m.group(1)
        d = json.loads(s[s.index("{") : s.rindex("}") + 1])
        label = str(d["label"]).upper()
        if label not in LABELS:
            raise ValueError(label)
        conf = min(1.0, max(0.0, float(d.get("confidence", 0.5))))
        cats = [str(c) for c in d.get("categories") or []]
        ev = [str(e) for e in d.get("evidence") or []]
        return label, conf, cats, ev, str(d.get("reasoning", "")), ""
    except Exception:
        return "SUSPICIOUS", 0.4, [], [], "", "parse_error"


def score_of(label: str, conf: float) -> float:
    if label == "MALICIOUS":
        return conf
    return 0.5 * conf if label == "SUSPICIOUS" else (1.0 - conf) * 0.2


def cache_key(model: str, prompt_sha: str, temperature: float, text_sha: str, run_index: int) -> str:
    return sha("\n".join([model, prompt_sha, str(temperature), text_sha, str(run_index)]))


class Cache:
    """SQLite result cache: key -> raw response + usage. Lets reruns and A/B resume for free."""

    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.execute("CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, "
                        "response TEXT, usage TEXT, created_at REAL)")

    def get(self, key: str):
        row = self.db.execute("SELECT response, usage FROM cache WHERE key=?", (key,)).fetchone()
        return (row[0], json.loads(row[1])) if row else None

    def put(self, key: str, response: str, usage: dict) -> None:
        self.db.execute("INSERT OR REPLACE INTO cache VALUES (?,?,?,?)",
                        (key, response, json.dumps(usage), time.time()))
        self.db.commit()


def fake_response(text_sha: str, run_index: int) -> str:
    """Deterministic stand-in for --dry-run, derived from the text hash only."""
    h = int(text_sha[:8], 16)
    return json.dumps({"label": LABELS[h % 3], "confidence": round(0.5 + (h % 50) / 100, 2),
                       "categories": ["dry_run"], "evidence": [], "reasoning": f"dry-run {run_index}"})


def call_api(client, model: str, system: str, user: str, temperature: float) -> tuple[str, dict]:
    for attempt in range(3):
        try:
            r = client.chat.completions.create(
                model=model, temperature=temperature, response_format={"type": "json_object"},
                messages=[{"role": "system", "content": system}, {"role": "user", "content": user}])
            u = r.usage
            return r.choices[0].message.content or "", {
                "prompt_tokens": u.prompt_tokens if u else 0, "completion_tokens": u.completion_tokens if u else 0}
        except Exception:
            if attempt == 2:
                raise
            time.sleep(2 ** attempt)


def skill_path(row: dict, data_root: str) -> Path | None:
    p = (row.get("path") or "").strip()
    if not p and row.get("dataset") == "maliciousskillbench":
        p = f"MaliciousSkillBench/text/{row['skill_id'].split(':', 1)[-1]}/SKILL.md"
    if not p:
        return None
    p = Path(data_root) / p
    return p if p.name.lower() == "skill.md" else p / "SKILL.md"


def judge_text(text: str, ctx: argparse.Namespace) -> dict:
    body, omitted = truncate(text)
    if ctx.mark:
        body = datamark(body, ctx.mark)
    user = f"{BEGIN}\n{body}\n{END}"
    tsha = sha(user)
    labels, scores, confs, cats, quotes, reasons, errors = [], [], [], set(), [], [], 0
    for i in range(ctx.runs):
        if ctx.dry_run:
            raw, usage = fake_response(tsha, i), {"prompt_tokens": 0, "completion_tokens": 0}
        else:
            key = cache_key(ctx.model, ctx.prompt_sha, ctx.temperature, tsha, i)
            hit = ctx.cache.get(key)
            if hit:
                raw, usage = hit
                ctx.usage["cache_hits"] += 1
            else:
                raw, usage = call_api(ctx.client, ctx.model, ctx.system, user, ctx.temperature)
                ctx.cache.put(key, raw, usage)
                ctx.usage["api_calls"] += 1
        ctx.usage["prompt_tokens"] += usage["prompt_tokens"]
        ctx.usage["completion_tokens"] += usage["completion_tokens"]
        label, conf, c, ev, reason, err = parse_response(raw)
        labels.append(label); confs.append(conf); scores.append(score_of(label, conf))
        cats.update(c); quotes.extend(q for q in ev if q not in quotes); reasons.append(reason)
        errors += bool(err)
    majority = max(Counter(labels).items(), key=lambda kv: (kv[1], -LABELS.index(kv[0])))[0]
    evidence = {"categories": sorted(cats), "evidence": quotes[:5],
                "reasoning": next((r for r in reasons if r), ""), "labels": labels,
                "runs": ctx.runs, "score_std": round(statistics.pstdev(scores), 4),
                "parse_errors": errors, "oversize": omitted > 0, "truncated_chars": omitted}
    return {"score": statistics.mean(scores), "verdict": majority, "confidence": statistics.mean(confs),
            "evidence": json.dumps(evidence, ensure_ascii=False),
            "error": "parse_error" if errors == ctx.runs else ""}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--prompt", required=True)
    ap.add_argument("--model", default=None, help="required unless --dry-run")
    ap.add_argument("--out", required=True)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--split", default=None, help="dev | test; default: all rows")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--base-url", default=None)
    ap.add_argument("--data-root", default="data/raw")
    ap.add_argument("--cache", default="runs/cache.sqlite")
    ap.add_argument("--temperature", type=float, default=0.0)
    ap.add_argument("--price-in", type=float, default=None, help="USD per MTok input")
    ap.add_argument("--price-out", type=float, default=None, help="USD per MTok output")
    ctx = ap.parse_args(argv)

    ctx.system, ctx.mark, ctx.prompt_sha = load_prompt(ctx.prompt)
    ctx.usage, ctx.client, ctx.cache = Counter(), None, None
    if not ctx.dry_run:
        if not ctx.model:
            ap.error("--model is required unless --dry-run")
        key = os.environ.get("OPENAI_API_KEY") or os.environ.get("SKILLSPLIT_LLM_API_KEY")
        if not key:
            ap.error("set OPENAI_API_KEY or SKILLSPLIT_LLM_API_KEY")
        from openai import OpenAI  # imported here so --dry-run and tests need no key
        ctx.client, ctx.cache = OpenAI(api_key=key, base_url=ctx.base_url), Cache(ctx.cache)
    ctx.model = ctx.model or "dry-run"

    with open(ctx.manifest, encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    if ctx.split:
        rows = [r for r in rows if r.get("split") == ctx.split]
    rows = rows[: ctx.limit] if ctx.limit else rows

    out_rows, t0 = [], time.time()
    for n, row in enumerate(rows, 1):
        rec = {"skill_id": row["skill_id"], "score": 0.0, "verdict": "", "confidence": "", "evidence": "", "error": ""}
        path = skill_path(row, ctx.data_root)
        if path is None or not path.is_file():
            rec["error"] = "file_not_found"
        else:
            try:
                rec.update(judge_text(path.read_text(encoding="utf-8", errors="replace"), ctx))
            except Exception as e:  # API failure after retries: score 0.0 + error (data-format.md)
                rec["error"] = f"api_error:{type(e).__name__}"
        out_rows.append(rec)
        if n % 25 == 0 or n == len(rows):
            print(f"[{n}/{len(rows)}] {time.time() - t0:.0f}s", file=sys.stderr)

    Path(ctx.out).parent.mkdir(parents=True, exist_ok=True)
    with open(ctx.out, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for r in out_rows:
            r["score"] = f"{float(r['score']):.4f}"
            r["confidence"] = f"{float(r['confidence']):.4f}" if r["confidence"] != "" else ""
            w.writerow(r)

    u = ctx.usage
    print(f"wrote {ctx.out}: {len(out_rows)} rows, verdicts {dict(Counter(r['verdict'] for r in out_rows))}, "
          f"errors {sum(bool(r['error']) for r in out_rows)}")
    print(f"model={ctx.model} prompt_sha={ctx.prompt_sha[:12]} runs={ctx.runs} datamark={ctx.mark!a} "
          f"api_calls={u['api_calls']} cache_hits={u['cache_hits']}")
    print(f"tokens: prompt={u['prompt_tokens']} completion={u['completion_tokens']}")
    if ctx.price_in is not None and ctx.price_out is not None:
        cost = u["prompt_tokens"] / 1e6 * ctx.price_in + u["completion_tokens"] / 1e6 * ctx.price_out
        print(f"estimated cost: ${cost:.4f} (at ${ctx.price_in}/MTok in, ${ctx.price_out}/MTok out)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
