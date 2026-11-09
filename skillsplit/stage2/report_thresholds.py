"""동결 자료용 집계: 문턱 후보별·출처별 분자/분모, 실패 장부, 네 칸, 결합, 비용. dev와 test에 같은 코드를 쓴다.

  python -m skillsplit.stage2.report_thresholds data/dev_labels.csv \
      --static runs/stage1_v0_dev.jsonl --llm runs/stage2_llm_v2_dev_r1.jsonl --jev runs/stage2_jev_v0_dev_r1.jsonl

결합은 "하나라도 걸면 걸림"이고, 아래 COMBOS를 결과와 상관없이 모두 낸다(test에서 좋은 조합만 고르지 않는다).
--exclude-ids: script-only 등 제외할 ID 파일(한 줄에 하나). 없으면 전체 기준.
"""
import argparse
import csv
import json
from collections import Counter
from pathlib import Path

from .summarize_runs import LLM_USD_PER_TOKEN, pr_auc, sources_of

LLM_CANDIDATES = [("0.5", 0.5), ("2/3", 2 / 3)]
JEV_CANDIDATES = [("0.3", 0.3), ("0.4", 0.4), ("0.5", 0.5), ("2/3", 2 / 3)]
FINAL_LLM, FINAL_JEV = ("2/3", 2 / 3), ("0.5", 0.5)  # decisions.md 2026-11-07
COMBOS = ["정적 또는 LLM", "정적 또는 Jev", "LLM 또는 Jev", "정적 또는 LLM 또는 Jev"]


def read_rows(path):
    return [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]


def fmt(n, d):
    return f"{n:,}/{d:,} ({n / d * 100:.2f}%)" if d else "0/0"


def check_ids(name, path, ids):
    """결과와 details 양쪽의 누락·중복·정답에 없는 ID를 센다."""
    for label, p in [("결과", Path(path)), ("details", Path(path).with_suffix(".details.jsonl"))]:
        if not p.exists():
            print(f"- {name} {label}: 파일 없음")
            continue
        c = Counter(r["skill_id"] for r in read_rows(p))
        print(f"- {name} {label}: {len(c):,}개, 누락 {len(ids - set(c))}, 중복 {sum(v > 1 for v in c.values())}, 정답에 없는 ID {len(set(c) - ids)}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("labels")
    ap.add_argument("--static", required=True)
    ap.add_argument("--llm", required=True)
    ap.add_argument("--jev", required=True)
    ap.add_argument("--exclude-ids")
    args = ap.parse_args()

    y = {r["benchmark_id"]: int(r["label"]) for r in csv.DictReader(open(args.labels, encoding="utf-8"))}
    if args.exclude_ids:
        skip = {line.strip() for line in open(args.exclude_ids, encoding="utf-8") if line.strip()}
        print(f"제외 ID {len(skip)}개 적용 (정답에 있는 것 {len(skip & set(y))}개)")
        y = {i: v for i, v in y.items() if i not in skip}
    ids = set(y)
    mal = [i for i in y if y[i]]
    ben = [i for i in y if not y[i]]
    src = sources_of(y, args.labels)

    print("## 입력 확인")
    for name, path in [("정적", args.static), ("LLM", args.llm), ("Jev", args.jev)]:
        check_ids(name, path, ids)

    static = {r["skill_id"]: r["score"] for r in read_rows(args.static)}
    llm = {r["skill_id"]: r["score"] for r in read_rows(args.llm)}
    jev = {r["skill_id"]: r["score"] for r in read_rows(args.jev)}
    llm_d = {r["skill_id"]: r for r in read_rows(Path(args.llm).with_suffix(".details.jsonl"))}
    jev_d = {r["skill_id"]: r for r in read_rows(Path(args.jev).with_suffix(".details.jsonl"))}
    llm_failed = {i for i in ids if llm_d[i]["parse_error"] or llm_d[i]["refused"]}
    jev_failed = {i for i in ids if jev_d[i]["failed"]}

    print("\n## 실패와 입력 생략")
    print(f"- LLM 실패 {len(llm_failed)}: 형식 오류 {sum(llm_d[i]['parse_error'] for i in ids)}(그중 답 끊김 {sum(llm_d[i]['cut_off'] and llm_d[i]['parse_error'] for i in ids)}), 거부 {sum(llm_d[i]['refused'] for i in ids)}. 악성 {sum(y[i] for i in llm_failed)}, 정상 {sum(not y[i] for i in llm_failed)}")
    print(f"- Jev 실패 {len(jev_failed)}: 악성 {sum(y[i] for i in jev_failed)}, 정상 {sum(not y[i] for i in jev_failed)}")
    print(f"- 입력 생략(잘림): LLM {sum(bool(llm_d[i]['omitted_chars']) for i in ids)}, Jev {sum(bool(jev_d[i]['omitted_chars']) for i in ids)}")

    def pred_static(i):
        return static[i] > 0

    def rows_for(preds):
        print("| 방법 | 기준 | 악성 잡음 | 정상 오탐 |\n|---|---|---|---|")
        for name, th_name, pred in preds:
            print(f"| {name} | {th_name} | {fmt(sum(pred(i) for i in mal), len(mal))} | {fmt(sum(pred(i) for i in ben), len(ben))} |")

    def by_th(scores, th):
        return lambda i: scores[i] >= th

    candidates = [("정적", "> 0", pred_static)]
    candidates += [("LLM", n, by_th(llm, t)) for n, t in LLM_CANDIDATES]
    candidates += [("Jev", n, by_th(jev, t)) for n, t in JEV_CANDIDATES]
    print("\n## 문턱 후보별 (전체)")
    rows_for(candidates)
    print(f"\nPR-AUC(보조): 정적 {pr_auc(static, y):.3f}, LLM {pr_auc(llm, y):.3f}, Jev {pr_auc(jev, y):.3f}")

    print("\n## 실패 장부: 실패를 어떻게 치느냐에 따른 성적 (실패 2/3은 지금 규칙에서 '차단'과 같다)")
    print("| 방법 | 기준 | 실패 처리 | 악성 잡음 | 정상 오탐 |\n|---|---|---|---|---|")
    for name, scores, failed, cands in [("LLM", llm, llm_failed, LLM_CANDIDATES), ("Jev", jev, jev_failed, [FINAL_JEV])]:
        for th_name, t in cands:
            for how in ["차단(지금 규칙)", "통과", "제외"]:
                keep = (lambda i: i not in failed) if how == "제외" else (lambda i: True)
                hit = (lambda i: scores[i] >= t and i not in failed) if how == "통과" else (lambda i: scores[i] >= t)
                m, b = [i for i in mal if keep(i)], [i for i in ben if keep(i)]
                print(f"| {name} | {th_name} | {how} | {fmt(sum(hit(i) for i in m), len(m))} | {fmt(sum(hit(i) for i in b), len(b))} |")

    print("\n## 출처별: 악성 잡음/악성 수, 오탐/정상 수")
    cols = [(f"{n} {th}", p) for n, th, p in candidates]
    print("| 출처 | 라벨 | N | " + " | ".join(c[0] for c in cols) + " |\n|" + "---|" * (3 + len(cols)))
    for lab, group, word in [(1, mal, "악성"), (0, ben, "정상")]:
        for s in sorted({src[i] for i in group}):
            sub = [i for i in group if src[i] == s]
            print(f"| {s} | {word} | {len(sub):,} | " + " | ".join(str(sum(p(i) for i in sub)) for _, p in cols) + " |")

    final_sets = [("최종 기준", FINAL_LLM, FINAL_JEV), ("LLM 0.5 병기", LLM_CANDIDATES[0], FINAL_JEV)]
    for title, (ln, lt), (jn, jt) in final_sets:
        pl, pj = by_th(llm, lt), by_th(jev, jt)
        print(f"\n## 네 칸 ({title}: LLM {ln}, Jev {jn}, 정적 > 0, 악성 {len(mal):,}개)")
        print("| 비교 | 둘 다 | 정적만 | 판정기만 | 둘 다 놓침 |\n|---|---|---|---|---|")
        for name, p in [("정적 × LLM", pl), ("정적 × Jev", pj)]:
            a = sum(pred_static(i) and p(i) for i in mal)
            b = sum(pred_static(i) and not p(i) for i in mal)
            c = sum(p(i) and not pred_static(i) for i in mal)
            print(f"| {name} | {a:,} | {b:,} | {c:,} | {len(mal) - a - b - c:,} |")
        print(f"\n결합 ({title}, 하나라도 걸면 걸림):")
        rows_for([
            (COMBOS[0], "", lambda i, p=pl: pred_static(i) or p(i)),
            (COMBOS[1], "", lambda i, p=pj: pred_static(i) or p(i)),
            (COMBOS[2], "", lambda i, p=pl, q=pj: p(i) or q(i)),
            (COMBOS[3], "", lambda i, p=pl, q=pj: pred_static(i) or p(i) or q(i)),
        ])

    print("\n## 토큰·시간·비용 (LLM은 토큰 × 가격 계산, Jev는 응답의 cost_usd)")
    li, lo = sum(llm_d[i]["input_tokens"] for i in ids), sum(llm_d[i]["output_tokens"] for i in ids)
    print(f"- LLM: 입력 {li:,}, 출력 {lo:,} 토큰, ${li * LLM_USD_PER_TOKEN['input'] + lo * LLM_USD_PER_TOKEN['output']:.2f}, 호출 시간 합 {sum(llm_d[i]['seconds'] for i in ids) / 3600:.2f}시간, 입력 토큰 최대 {max(llm_d[i]['input_tokens'] for i in ids):,}")
    # Jev 실패 기록에는 input_tokens가 없고 cost_usd는 0으로 적힌다. 0으로 확인된 것이 아니라 모르는 것이므로 합계에서 빼고 건수를 따로 낸다.
    jev_known = [jev_d[i] for i in ids if jev_d[i].get("input_tokens") is not None]
    print(f"- Jev: 입력 {sum(r['input_tokens'] for r in jev_known):,} 토큰, ${sum(r['cost_usd'] or 0 for r in jev_known):.2f}, 호출 시간 합 {sum(jev_d[i]['seconds'] for i in ids) / 3600:.2f}시간, 입력 토큰 최대 {max((r['input_tokens'] for r in jev_known), default=0):,}, 사용량 모름 {len(ids) - len(jev_known)}건(토큰 기록이 없어 합계·최대에서 뺌. 0으로 확인된 것이 아님)")
    print(f"- 모델: LLM {dict(Counter(llm_d[i]['model'] for i in ids))}, Jev {dict(Counter(jev_d[i]['model'] for i in ids))}")


if __name__ == "__main__":
    main()
