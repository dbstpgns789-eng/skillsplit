"""2단계 판정 결과를 한 번에 집계한다: 성능(두 걸림 기준), 흔들림, 비용·실패, 정적과의 네 칸, LLM-Jev 비교, 출처별.

  python -m skillsplit.stage2.summarize_runs data/dev100_labels.csv runs/stage1_v0_dev100.jsonl --llm v2
  python -m skillsplit.stage2.summarize_runs data/devcheck100_labels.csv runs/stage1_v0_devcheck100.jsonl --data devcheck100 --llm v2

읽는 파일: runs/stage2_llm_<버전>_<데이터>_r<N>.jsonl, runs/stage2_jev_v0_<데이터>_r<N>.jsonl 과 각각의 .details.jsonl.
있는 회차(r1, r2, ...)만 읽고, 여러 회면 평균 점수로 판정한다. Jev 결과가 없으면 Jev는 건너뛴다.
걸림 기준: 정적 score > 0 (10/12 합의). 2단계는 0.5와 2/3을 나란히 낸다(LLM에서 0.5는 SUSPICIOUS 확신 0.5 이상부터, 2/3은 MALICIOUS만).
"""
import argparse
import csv
import json
import statistics as st
from collections import defaultdict
from pathlib import Path

RUNS = Path("runs")
LLM_USD_PER_TOKEN = {"input": 1e-6, "output": 5e-6}  # claude-haiku-4.5 (Vercel 가격 = Anthropic 가격)
THRESHOLDS = {"0.5": 0.5, "2/3": 2 / 3}  # LLM에서 2/3은 MALICIOUS만 걸림. Jev에서는 확률 2/3


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


def caught(scores, ids, th):
    return sum(scores[i] >= th for i in ids)


def sources_of(y, labels_path):
    """skill_id → 출처. 정답 파일에 source_id가 없으면 data/skills.csv에서 찾는다."""
    rows = list(csv.DictReader(open(labels_path, encoding="utf-8")))
    if "source_id" in rows[0]:
        return {r["benchmark_id"]: r["source_id"] for r in rows}
    csv.field_size_limit(10**9)
    return {r["benchmark_id"]: r["source_id"] for r in csv.DictReader(open("data/skills.csv", encoding="utf-8", newline=""))
            if r["benchmark_id"] in y}


def run_files(ver, version, data):
    n = 1
    while (RUNS / f"stage2_{ver}_{version}_{data}_r{n}.jsonl").exists():
        n += 1
    return [(RUNS / f"stage2_{ver}_{version}_{data}_r{r}.jsonl", RUNS / f"stage2_{ver}_{version}_{data}_r{r}.details.jsonl")
            for r in range(1, n)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("labels", help="정답 파일 (benchmark_id, label)")
    ap.add_argument("static", help="정적 탐지기 결과 (같은 데이터)")
    ap.add_argument("--data", default="dev100", help="결과 파일 이름 속 데이터 이름")
    ap.add_argument("--llm", default="v2", help="LLM 프롬프트 버전")
    args = ap.parse_args()

    y = {r["benchmark_id"]: int(r["label"]) for r in csv.DictReader(open(args.labels, encoding="utf-8"))}
    static = {k: v["score"] for k, v in load(args.static).items()}
    mal = sorted(i for i in y if y[i])
    ben = sorted(i for i in y if not y[i])
    src = sources_of(y, args.labels)
    mean = {}

    for ver, version in (("llm", args.llm), ("jev", "v0")):
        files = run_files(ver, version, args.data)
        if not files:
            print(f"\n== {ver} {version}: 결과 없음, 건너뜀 ==")
            continue
        runs = [load(f) for f, _ in files]
        details = [load(d) for _, d in files]
        scores = [{i: run[i]["score"] for i in y} for run in runs]
        m = mean[ver] = {i: st.mean(s[i] for s in scores) for i in y}

        print(f"\n== {ver} {version} ({details[0][mal[0]]['model']}), {args.data}, {len(runs)}회 ==")
        for r, s in enumerate(scores, 1):
            parts = "  ".join(f"{k} 기준 악성 {caught(s, mal, t)}/{len(mal)}·오탐 {caught(s, ben, t)}/{len(ben)}"
                              for k, t in THRESHOLDS.items())
            print(f"r{r}: PR-AUC {pr_auc(s, y):.3f}  {parts}")
        if len(runs) > 1:
            parts = "  ".join(f"{k} 기준 악성 {caught(m, mal, t)}/{len(mal)}·오탐 {caught(m, ben, t)}/{len(ben)}"
                              for k, t in THRESHOLDS.items())
            print(f"평균: PR-AUC {pr_auc(m, y):.3f}  {parts}")
            same = sum(len({s[i] for s in scores}) == 1 for i in y)
            flips = [i for i in y if len({s[i] >= 0.5 for s in scores}) > 1]
            print(f"흔들림: 모든 회차 점수가 같음 {same}/{len(y)}, 0.5를 넘나듦 {len(flips)} {flips}")

        rows = [d[i] for d in details for i in y]
        print(f"1건 시간 중간값 {st.median(x['seconds'] for x in rows):.2f}초")
        if ver == "llm":
            usd = sum(x["input_tokens"] * LLM_USD_PER_TOKEN["input"] + x["output_tokens"] * LLM_USD_PER_TOKEN["output"] for x in rows)
            dropped = sum(x["evidence_dropped"] for x in rows)
            kept = sum(len(run[i]["evidence"]) for run in runs for i in y)
            print(f"비용 ${usd:.3f} ({len(rows)}건)  형식 오류 {sum(x['parse_error'] for x in rows)}  거부 {sum(x['refused'] for x in rows)}"
                  f"  답 끊김 {sum(x.get('cut_off', False) for x in rows)}  근거 인용 버림 {dropped}/{dropped + kept}")
        else:
            print(f"비용 ${sum(x['cost_usd'] for x in rows):.4f} ({len(rows)}건)  실패 {sum(x.get('failed', False) for x in rows)}")

        cells = {"둘 다": 0, "정적만": 0, "판정기만": 0, "둘 다 놓침": 0}
        for i in mal:
            a, b = static[i] > 0, m[i] >= 0.5
            cells["둘 다" if a and b else "정적만" if a else "판정기만" if b else "둘 다 놓침"] += 1
        print(f"정적 × {ver} 네 칸(악성 {len(mal)}, 판정기 0.5 기준): {cells}")

    print(f"\n정적: 악성 {sum(static[i] > 0 for i in mal)}/{len(mal)}, 정상 오탐 {sum(static[i] > 0 for i in ben)}/{len(ben)}, "
          f"PR-AUC {pr_auc(static, y):.3f}")
    if len(mean) == 2:
        llm, jev = mean["llm"], mean["jev"]
        print(f"LLM-Jev 판정 일치(0.5) {sum((llm[i] >= 0.5) == (jev[i] >= 0.5) for i in y)}/{len(y)}")
        print("악성 중 LLM만 잡음", [i for i in mal if llm[i] >= 0.5 > jev[i]])
        print("악성 중 Jev만 잡음", [i for i in mal if jev[i] >= 0.5 > llm[i]])
    print("악성 중 모두 놓침(정적·판정기, 0.5)", [i for i in mal if static[i] == 0 and all(mean[v][i] < 0.5 for v in mean)])

    # 출처별: 개선이 한두 출처에서만 나온 것인지 보려고 (팀 보충 10/27, PR #6 리뷰 4번)
    print("\n출처별 (판정기는 0.5 기준, 괄호는 2/3 기준)")
    by = defaultdict(list)
    for i in y:
        by[(src.get(i, "?"), y[i])].append(i)
    for (s, lab), ids in sorted(by.items(), key=lambda kv: (-kv[0][1], kv[0][0])):
        kind = "악성 잡음" if lab else "정상 오탐"
        parts = [f"정적 {sum(static[i] > 0 for i in ids)}"]
        for v in mean:
            parts.append(f"{v} {caught(mean[v], ids, 0.5)}({caught(mean[v], ids, 2 / 3)})")
        print(f"  {s} {kind}: n={len(ids)}  " + "  ".join(parts))


if __name__ == "__main__":
    main()
