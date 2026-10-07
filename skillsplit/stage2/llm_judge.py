"""2단계 설명서 판정기 - LLM 버전 (v0).

스킬 폴더마다 SKILL.md를 읽어 LLM에게 SAFE / SUSPICIOUS / MALICIOUS와 확신도를 받고,
팀 공통 형식의 점수(0~1)로 바꿔 결과 파일에 쓴다.

쓰는 법
  python -m skillsplit.stage2.llm_judge data/dev100 --out runs/stage2_llm_v0_dev100.jsonl
  python -m skillsplit.stage2.llm_judge data/dev100 --out runs/smoke.jsonl --backend cli --limit 5

backend
  api : Anthropic API. ANTHROPIC_API_KEY 필요. 최종 측정은 이것으로 한다(temperature 0 고정 가능).
  cli : 로컬 claude CLI. API 키 없이 코드가 끝까지 도는지 확인하는 시험용. temperature를 고정할 수 없어
        재현성이 약하므로 보고서 수치로 쓰지 않는다.
"""
import argparse
import json
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from .common import append_jsonl, done_ids, list_skills, read_skill, truncate, write_result

PROMPT_VERSION = "v0"
PROMPT_FILE = Path(__file__).parent / "prompt_v0.txt"
SYSTEM_PROMPT = PROMPT_FILE.read_text(encoding="utf-8")
DEFAULT_MODEL = "claude-haiku-4-5"  # R2 C5의 2순위. 소형 모델로 비용 추정(R2 B3)과 맞춘다.

# 파싱 실패나 거부 때 쓰는 값. R2 C3처럼 "안전"으로 넘기지 않고 SUSPICIOUS 0.4로 둔다(fail-closed).
FAIL_CLOSED = {"classification": "SUSPICIOUS", "confidence": 0.4, "risk_tags": [], "evidence": [], "reasoning": ""}


def user_message(text):
    return f"<<<SKILL_MD_BEGIN>>>\n{text}\n<<<SKILL_MD_END>>>\n\nClassify the skill above."


def to_score(classification, confidence):
    """3단 라벨 + 확신도 -> 악성 쪽 점수 0~1 (v0 규칙).

    SAFE는 0~1/3, SUSPICIOUS는 1/3~2/3, MALICIOUS는 2/3~1 구간에 놓는다.
    SAFE는 확신이 클수록 0에 가깝고, 나머지는 확신이 클수록 위로 간다.
    점수가 있어야 PR-AUC와 FPR 1% 재현율을 계산할 수 있다.
    """
    c = min(max(float(confidence), 0.0), 1.0)
    if classification == "SAFE":
        return (1 - c) / 3
    if classification == "MALICIOUS":
        return 2 / 3 + c / 3
    return 1 / 3 + c / 3  # SUSPICIOUS, 또는 알 수 없는 라벨


def parse_verdict(raw):
    """모델 답에서 JSON 객체 하나를 꺼낸다. 실패하면 None."""
    m = re.search(r"\{.*\}", raw or "", re.S)
    if not m:
        return None
    try:
        v = json.loads(m.group(0))
    except json.JSONDecodeError:
        return None
    if v.get("classification") not in ("SAFE", "SUSPICIOUS", "MALICIOUS"):
        return None
    return v


def _norm(s):
    return re.sub(r"\s+", " ", s).strip().lower()


def verify_evidence(quotes, text):
    """근거 인용이 원문에 실제로 있는지 검사한다(R2 C3). 없는 인용은 모델이 지어낸 것이라 버린다."""
    body = _norm(text)
    kept = [q for q in quotes if isinstance(q, str) and q.strip() and _norm(q) in body]
    return kept, len(quotes) - len(kept)


def call_api(client, model, text):
    kwargs = {"temperature": 0} if "haiku" in model else {}  # 최신 Opus·Sonnet은 temperature를 받지 않는다
    msg = client.messages.create(
        model=model, max_tokens=512, system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message(text)}], **kwargs)
    raw = "".join(b.text for b in msg.content if b.type == "text")
    usage = {"input_tokens": msg.usage.input_tokens, "output_tokens": msg.usage.output_tokens}
    return raw, msg.stop_reason == "refusal", usage, msg.model


def call_cli(model, text, workdir):
    """claude CLI를 도구 없이, 사용자 설정 없이 한 번 부른다. 스킬 내용은 표준입력으로만 들어간다."""
    cmd = [shutil.which("claude"), "-p", "--model", model, "--restricted", "--setting-sources", "",
           "--no-session-persistence", "--output-format", "json", "--system-prompt-file", str(PROMPT_FILE),
           "--disallowedTools", "Read Write Edit Glob Grep WebFetch WebSearch Task Agent NotebookEdit"]
    p = subprocess.run(cmd, input=user_message(text), capture_output=True, text=True,
                       encoding="utf-8", cwd=workdir, timeout=180)
    try:
        out = json.loads(p.stdout)
    except json.JSONDecodeError:
        return p.stdout + p.stderr, False, {}, model
    usage = out.get("usage", {})
    used = next(iter(out.get("modelUsage", {})), model)
    return (out.get("result") or "", out.get("stop_reason") == "refusal",
            {"input_tokens": usage.get("input_tokens"), "output_tokens": usage.get("output_tokens")}, used)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("skills_root", help="스킬 폴더들이 들어 있는 폴더 (예: data/dev100)")
    ap.add_argument("--out", required=True, help="결과 파일(.jsonl). 같은 이름의 .details.jsonl도 생긴다")
    ap.add_argument("--backend", choices=["api", "cli"], default="api")
    ap.add_argument("--model", default=None, help=f"기본: api={DEFAULT_MODEL}, cli=haiku")
    ap.add_argument("--limit", type=int, default=None, help="앞에서부터 N개만 (시험용)")
    args = ap.parse_args()

    model = args.model or (DEFAULT_MODEL if args.backend == "api" else "haiku")
    details_path = Path(args.out).with_suffix(".details.jsonl")
    skip = done_ids(args.out)
    folders = [f for f in list_skills(args.skills_root) if f.name not in skip][: args.limit]

    client = None
    if args.backend == "api":
        import anthropic
        client = anthropic.Anthropic()
    workdir = tempfile.mkdtemp(prefix="stage2_cli_")  # cli는 빈 폴더에서 실행: 저장소 파일을 못 보게

    for i, folder in enumerate(folders, 1):
        skill_id, original = read_skill(folder)
        text, omitted = truncate(original)
        t0 = time.time()
        if args.backend == "api":
            raw, refused, usage, used_model = call_api(client, model, text)
        else:
            raw, refused, usage, used_model = call_cli(model, text, workdir)
        parsed = None if refused else parse_verdict(raw)
        v = parsed or FAIL_CLOSED
        evidence, dropped = verify_evidence(v.get("evidence") or [], original)
        score = to_score(v["classification"], v.get("confidence", 0.5))

        write_result(args.out, skill_id, score, evidence)
        append_jsonl(details_path, {
            "skill_id": skill_id, "prompt_version": PROMPT_VERSION, "backend": args.backend,
            "model": used_model, "classification": v["classification"], "confidence": v.get("confidence"),
            "risk_tags": v.get("risk_tags", []), "reasoning": v.get("reasoning", ""),
            "refused": refused, "parse_error": parsed is None and not refused,
            "evidence_dropped": dropped, "omitted_chars": omitted,
            "seconds": round(time.time() - t0, 2), **usage,
            "raw_if_failed": None if parsed else (raw or "")[:1000],  # 실패 원인을 나중에 볼 수 있게
        })
        print(f"[{i}/{len(folders)}] {skill_id} {v['classification']} score={score:.3f}"
              f"{' REFUSED' if refused else ''}{' PARSE_ERROR' if parsed is None and not refused else ''}")


if __name__ == "__main__":
    main()
