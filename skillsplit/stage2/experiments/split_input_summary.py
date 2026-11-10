"""split_input.py 결과 집계. 쓰는 법: python skillsplit/stage2/experiments/split_input_summary.py <출력 폴더>  (결과는 <출력 폴더>/summary.txt)"""
import json
import sys
from collections import defaultdict
from pathlib import Path

OUT = Path(sys.argv[1])
calls = [json.loads(l) for l in open(OUT / "calls.jsonl", encoding="utf-8")]
docs = {d["doc_id"]: d for d in (json.loads(l) for l in open(OUT / "docs.jsonl", encoding="utf-8"))}
CONDS = "ABPK"
FAIL = 2 / 3

by = defaultdict(lambda: defaultdict(list))  # doc -> cond -> [call]
for c in calls:
    by[c["doc_id"]][c["cond"]].append(c)


def score(doc, cond):
    """조각 조건은 최댓값. 실패한 호출은 판정기 규칙대로 2/3."""
    return max(FAIL if c["score"] is None else c["score"] for c in by[doc][cond])


lines = []
p = lines.append
p(f"호출 {len(calls)}, 실패 " + ", ".join(f"{k} {sum(c['score'] is None for c in calls if c['cond'] == k)}" for k in CONDS))

p("\n[syn] 바탕 글 5개, 걸림 기준 0.5. 칸 = 걸린 수/5 (점수 5개)")
for kind in ["clean", "explicit", "split_camo", "same_para"]:
    ids = [d for d in docs if d.endswith("__" + kind)]
    row = []
    for k in CONDS:
        s = [score(d, k) for d in ids]
        row.append(f"{k} {sum(x >= .5 for x in s)}/5 ({' '.join(f'{x:.2f}' for x in s)})")
    p(f"{kind:<11} " + " | ".join(row))

p("\n[syn] 조각 조건에서 악성 조각 점수 vs 나머지 조각 최댓값")
for kind in ["explicit", "split_camo", "same_para"]:
    for k in "PK":
        att, rest = [], []
        for d in (d for d in docs if d.endswith("__" + kind)):
            cs = by[d][k]
            att.append(max((c["score"] or 0) for c in cs if c["has_attack"]))
            rest.append(max((c["score"] or 0) for c in cs if not c["has_attack"]))
        p(f"{kind:<11} {k}: 악성 조각 {' '.join(f'{x:.2f}' for x in att)} / 나머지 최댓값 {' '.join(f'{x:.2f}' for x in rest)}")

p("\n[dev100] 걸림 기준 0.5: 악성 잡음/50, 정상 오탐/50")
dev = [d for d in docs if docs[d]["group"] == "dev100"]
for k in CONDS:
    mal = [d for d in dev if docs[d]["label"] == 1]
    ben = [d for d in dev if docs[d]["label"] == 0]
    p(f"{k}: 악성 {sum(score(d, k) >= .5 for d in mal)}/50, 오탐 {sum(score(d, k) >= .5 for d in ben)}/50")
for name, cond in [("12,000자 이하", lambda n: n <= 12000), ("12,000자 초과", lambda n: n > 12000)]:
    sub = [d for d in dev if cond(docs[d]["chars"])]
    mal = [d for d in sub if docs[d]["label"] == 1]
    ben = [d for d in sub if docs[d]["label"] == 0]
    p(f"  {name} (악성 {len(mal)}, 정상 {len(ben)}): " + " | ".join(
        f"{k} 악성 {sum(score(d, k) >= .5 for d in mal)} 오탐 {sum(score(d, k) >= .5 for d in ben)}" for k in CONDS))
nP = sorted(len(by[d]["P"]) for d in dev)
nK = sorted(len(by[d]["K"]) for d in dev)
p(f"  스킬당 조각 수 중앙값: P {nP[len(nP) // 2]}, K {nK[len(nK) // 2]}")

short = [d for d in dev if docs[d]["chars"] <= 12000]
diff = [d for d in short if abs(score(d, "A") - score(d, "B")) > 1e-9]
flip = [d for d in short if (score(d, "A") >= .5) != (score(d, "B") >= .5)]
p(f"\n[흔들림] 12,000자 이하 {len(short)}개는 A와 B 입력이 같다: 점수 다름 {len(diff)}, 0.5 넘나듦 {len(flip)}")

p("\n[dev100] 정상인데 조각 조건에서 새로 걸린 것 (A < 0.5, P 또는 K ≥ 0.5)")
for d in dev:
    if docs[d]["label"] == 0 and score(d, "A") < .5 and (score(d, "P") >= .5 or score(d, "K") >= .5):
        p(f"  {d} A {score(d, 'A'):.2f} P {score(d, 'P'):.2f} K {score(d, 'K'):.2f} 조각 {len(by[d]['P'])}/{len(by[d]['K'])}")
p("\n[dev100] 악성인데 A가 놓치고 조각 조건에서 잡힌 것")
for d in dev:
    if docs[d]["label"] == 1 and score(d, "A") < .5 and (score(d, "P") >= .5 or score(d, "K") >= .5):
        p(f"  {d} {docs[d]['chars']}자 A {score(d, 'A'):.2f} B {score(d, 'B'):.2f} P {score(d, 'P'):.2f} K {score(d, 'K'):.2f}")

(OUT / "summary.txt").write_text("\n".join(lines), encoding="utf-8")
print("ok")
