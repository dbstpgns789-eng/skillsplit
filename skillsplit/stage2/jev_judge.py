"""2단계 설명서 판정기 - Jev 버전 (v0).

Jev는 글을 쓰지 않고, 정해진 질문에 확률로 답하는 TypeSafe의 판정 모델이다.
질문은 jev_questions_v0.json에 있다(jev-skillbench의 질문을 옮긴 것).
점수는 is_malicious 질문의 확률(noul)을 그대로 쓴다.

쓰는 법
  python -m skillsplit.stage2.jev_judge data/dev100 --out runs/stage2_jev_v0_dev100.jsonl --via vercel --limit 1

via (세 경로 모두 요청 본문은 {"model", "state", "questions"}로 같고, 주소와 키만 다르다)
  typesafe   : https://api.typesafe.ai/v1/systemone            키 TYPESAFE_API_KEY
  vercel     : https://ai-gateway.vercel.sh/typesafe/v1/systemone   키 AI_GATEWAY_API_KEY
  openrouter : https://openrouter.ai/api/alpha/decisions         키 OPENROUTER_API_KEY (크레딧 필요)
"""
import argparse
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

from .common import append_jsonl, done_ids, list_skills, read_skill, truncate, write_result

QUESTIONS_VERSION = "v0"
QUESTIONS = {k: v for k, v in json.loads(
    (Path(__file__).parent / "jev_questions_v0.json").read_text(encoding="utf-8")).items() if not k.startswith("_")}

VIA = {
    "typesafe": ("https://api.typesafe.ai/v1/systemone", "jev-latest", "TYPESAFE_API_KEY"),
    "vercel": ("https://ai-gateway.vercel.sh/typesafe/v1/systemone", "typesafe-ai/jev", "AI_GATEWAY_API_KEY"),
    "openrouter": ("https://openrouter.ai/api/alpha/decisions", "~typesafe/jev-latest", "OPENROUTER_API_KEY"),
}
USD_PER_INPUT_TOKEN = 0.042 / 1_000_000  # Jev는 입력 100만 토큰당 $0.042, 출력 무료
# 끝까지 실패한 스킬의 점수. llm_judge.FAIL_SCORE와 같은 규칙: 실패를 안전으로 넘기지 않는다.
# 예전에는 실패하면 결과 줄을 쓰지 않아 스킬이 결과 파일에서 빠졌다.
FAIL_SCORE = 2 / 3
RETRY_WAITS = (5, 15, 45)  # 일시적 오류(429, 5xx, 연결·시간 초과)를 다시 보내기 전에 기다리는 초


def make_state(text):
    """Jev에 넘길 상태. 스킬 이름(benchmark_id)은 넣지 않는다.
    벤치마크 ID나 출처 정보가 들어가면 판정기가 내용 대신 그것을 보고 맞힐 수 있다(라벨 누출, R2 C1-5)."""
    return {"skill": {"files": [{"path": "SKILL.md", "content": text}]}}


def call_jev(url, model, key, text):
    body = json.dumps({"model": model, "state": make_state(text), "questions": QUESTIONS}).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=90) as r:
        return json.loads(r.read().decode("utf-8"))


def ask_jev(url, model, key, text):
    """(payload, 오류 문자열). 일시적 오류는 기다렸다가 최대 3번 다시 보낸다.
    다시 보내도 같을 오류(4xx, 답 모양이 다름)는 바로 실패로 돌려준다."""
    for wait in RETRY_WAITS + (None,):
        try:
            payload = call_jev(url, model, key, text)
            float(payload["answers"]["is_malicious"]["noul"])  # 점수로 쓸 답이 있는지 확인
            return payload, None
        except urllib.error.HTTPError as e:
            error = f"HTTP {e.code}: {e.read()[:200]!r}"
            if e.code != 429 and e.code < 500:
                return None, error
        except (urllib.error.URLError, TimeoutError) as e:
            error = f"{type(e).__name__}: {e}"
        except (KeyError, TypeError, ValueError) as e:
            return None, f"답 모양이 다름: {e!r}"
        if wait is None:
            return None, error
        time.sleep(wait)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("skills_root")
    ap.add_argument("--out", required=True)
    ap.add_argument("--via", choices=list(VIA), default="vercel")
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()

    url, model, key_env = VIA[args.via]
    key = os.environ.get(key_env)
    if not key:
        raise SystemExit(f"{key_env} 환경변수가 없습니다. 1주차 'Jev 접근 확보'에서 받은 키를 넣어 주세요.")
    if not key.isascii() or " " in key:
        raise SystemExit(f"{key_env}에 한글이나 공백이 들어 있습니다. 설명용 예시가 아니라 Vercel에서 복사한 실제 키를 넣어 주세요.")

    details_path = Path(args.out).with_suffix(".details.jsonl")
    skip = done_ids(args.out)
    folders = [f for f in list_skills(args.skills_root) if f.name not in skip][: args.limit]

    for i, folder in enumerate(folders, 1):
        skill_id, original = read_skill(folder)
        text, omitted = truncate(original)
        t0 = time.time()
        payload, error = ask_jev(url, model, key, text)
        if error:
            write_result(args.out, skill_id, FAIL_SCORE, [f"jev_failed: {error[:100]}"])
            append_jsonl(details_path, {
                "skill_id": skill_id, "questions_version": QUESTIONS_VERSION, "via": args.via, "model": model,
                "failed": True, "error": error, "prob_malicious": None, "omitted_chars": omitted,
                "cost_usd": 0, "seconds": round(time.time() - t0, 2),
            })
            print(f"[{i}/{len(folders)}] {skill_id} FAILED {error[:100]}")
            continue
        answers = payload.get("answers", {})
        prob = float(answers["is_malicious"]["noul"])
        vector = answers.get("attack_vector", {})
        severity = answers.get("harm_severity", {})
        evidence = [f"attack_vector={vector.get('choice')} ({vector.get('confidence', 0):.2f})",
                    f"harm_severity={severity.get('score', 0):.2f} / 3"]

        write_result(args.out, skill_id, prob, evidence)
        usage = payload.get("usage") or {}
        append_jsonl(details_path, {
            "skill_id": skill_id, "questions_version": QUESTIONS_VERSION, "via": args.via,
            "model": payload.get("model", model), "failed": False, "prob_malicious": prob,
            "attack_vector": vector.get("choice"), "vector_probs": vector.get("probabilities"),
            "harm_severity": severity.get("score"), "omitted_chars": omitted,
            "input_tokens": usage.get("input_tokens"),
            "cost_usd": usage.get("cost") or (usage.get("input_tokens") or 0) * USD_PER_INPUT_TOKEN,
            "seconds": round(time.time() - t0, 2),
        })
        print(f"[{i}/{len(folders)}] {skill_id} p(malicious)={prob:.3f} vector={vector.get('choice')}")


if __name__ == "__main__":
    main()
