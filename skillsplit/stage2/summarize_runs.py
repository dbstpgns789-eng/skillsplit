"""2단계 3회 판정 결과를 한 번에 집계한다: 성능, 흔들림, 비용, 정적과의 네 칸, LLM-Jev 비교.

  python -m skillsplit.stage2.summarize_runs data/dev100_labels.csv runs/stage1_v0_dev100.jsonl

읽는 파일: runs/stage2_{llm,jev}_v0_dev100_r{1,2,3}.jsonl 과 각각의 .details.jsonl
"걸림" 기준은 2026-10-12 합의대로 정적 score > 0, 2단계 score >= 0.5. 세 번의 평균 점수로 판정한다.
"""
import csv
import json
import statistics as st
import sys
from pathlib import Path

RUNS = Path("runs")
LLM_USD_PER_TOKEN = {"input": 1e-6, "output": 5e-6}  # claude-haiku-4.5 (Vercel 가격 = Anthropic 가격)


def load(path):
    return {json.loads(line)["skill_id"]: json.loads(line) for line in open(path, encoding="utf-8") if line.strip()}


def pr_auc(scores, y):
    """평균 정밀도. 점수가 같은 스킬은 한 문턱으로 묶는다."""
    pos = sum(y.values())
    area, prev = 0.0, 0.0
    for t in sorted(set(scores.values()), reverse=True):
        sel = [i for i in y if scores[i] >= t]
        tp = sum(y[i] for i in sel)
        area += (tp / pos - prev) * (tp / len(sel))
        prev = tp / pos
    return area


def caught(scores, y, th):
    """(잡은 악성 수, 잘못 잡은 정상 수)"""
    return sum(scores[i] >= th for i in y if y[i]), sum(scores[i] >= th for i in y if not y[i])


def main():
    y = {r["benchmark_id"]: int(r["label"]) for r in csv.DictReader(open(sys.argv[1], encoding="utf-8"))}
    static = {k: v["score"] for k, v in load(sys.argv[2]).items()}
    mal = sorted(i for i in y if y[i])
    mean = {}

    for ver in ("llm", "jev"):
        runs = [load(RUNS / f"stage2_{ver}_v0_dev100_r{r}.jsonl") for r in (1, 2, 3)]
        details = [load(RUNS / f"stage2_{ver}_v0_dev100_r{r}.details.jsonl") for r in (1, 2, 3)]
        scores = [{i: run[i]["score"] for i in y} for run in runs]
        mean[ver] = {i: st.mean(s[i] for s in scores) for i in y}
        m = mean[ver]

        print(f"\n== {ver} ({details[0][mal[0]]['model']}) ==")
        for r, s in enumerate(scores, 1):
            print(f"r{r}: PR-AUC {pr_auc(s, y):.3f}  0.5 기준 악성 {caught(s, y, 0.5)[0]}/50, 정상 오탐 {caught(s, y, 0.5)[1]}/50")
        tp, fp = caught(m, y, 0.5)
        print(f"세 번 평균: PR-AUC {pr_auc(m, y):.3f}  0.5 기준 악성 {tp}/50, 정상 오탐 {fp}/50")

        same = sum(len({s[i] for s in scores}) == 1 for i in y)
        flips = [i for i in y if len({s[i] >= 0.5 for s in scores}) > 1]
        print(f"흔들림: 세 번 점수가 모두 같음 {same}/100, 0.5를 넘나듦 {len(flips)} {flips}")

        rows = [d[i] for d in details for i in y]
        print(f"1건 시간 중간값 {st.median(x['seconds'] for x in rows):.2f}초")
        if ver == "llm":
            usd = sum(x["input_tokens"] * LLM_USD_PER_TOKEN["input"] + x["output_tokens"] * LLM_USD_PER_TOKEN["output"] for x in rows)
            dropped = sum(x["evidence_dropped"] for x in rows)
            kept = sum(len(run[i]["evidence"]) for run in runs for i in y)
            print(f"비용 ${usd:.3f} (300건)  형식 오류 {sum(x['parse_error'] for x in rows)}  거부 {sum(x['refused'] for x in rows)}"
                  f"  답 끊김 {sum(x['cut_off'] for x in rows)}  근거 인용 버림 {dropped}/{dropped + kept}")
        else:
            print(f"비용 ${sum(x['cost_usd'] for x in rows):.4f} (300건)")

        cells = {"둘 다": 0, "정적만": 0, "판정기만": 0, "둘 다 놓침": 0}
        for i in mal:
            a, b = static[i] > 0, m[i] >= 0.5
            cells["둘 다" if a and b else "정적만" if a else "판정기만" if b else "둘 다 놓침"] += 1
        print(f"정적 × {ver} 네 칸(악성 50): {cells}")

    tp_s, fp_s = sum(static[i] > 0 for i in mal), sum(static[i] > 0 for i in y if not y[i])
    print(f"\n정적: 악성 {tp_s}/50, 정상 오탐 {fp_s}/50, PR-AUC {pr_auc(static, y):.3f}")
    llm, jev = mean["llm"], mean["jev"]
    print(f"LLM-Jev 판정 일치 {sum((llm[i] >= 0.5) == (jev[i] >= 0.5) for i in y)}/100")
    print("악성 중 LLM만 잡음", [i for i in mal if llm[i] >= 0.5 > jev[i]])
    print("악성 중 Jev만 잡음", [i for i in mal if jev[i] >= 0.5 > llm[i]])
    print("악성 중 둘 다 놓침", [i for i in mal if max(llm[i], jev[i]) < 0.5 and static[i] == 0], "(정적까지 포함)")


if __name__ == "__main__":
    main()
