# 정적 탐지기 v0 규칙 채택 보고서 (skillsplit/stage1/README.md §4). dev 전체에 돌려 규칙별·전체 수치를 낸다. 원문은 출력하지 않는다.
# 필요: dev_skills/(make_dev.py), runs_dev/scores.csv(E1), dev100_labels.csv(sample.py)
# 사용: cd data && python s1_rule_report.py → runs_dev/s1_v0_rules.csv, runs_dev/s1_v0_samples.csv
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from skillsplit.stage1.rules import RULES
from skillsplit.stage1.scan import scan_text
from skillsplit.stage2.common import read_skill

MIN_SOURCE_HITS = 3   # 출처 하나로 셀 최소 악성 적중 수
MAX_BENIGN_RATE = 0.01
MAX_FPR = 0.02


def pr_auc(y, s):
    """sklearn average_precision_score와 같은 계산(같은 점수는 한 문턱으로 묶음)."""
    d = pd.DataFrame({"y": y, "s": s}).groupby("s")["y"].agg(["sum", "count"]).iloc[::-1]
    tp, n = d["sum"].cumsum(), d["count"].cumsum()
    prec, rec = tp / n, tp / d["sum"].sum()
    return float(((rec - rec.shift(fill_value=0)) * prec).sum())


def run(m, rules):
    rows = []
    for b in m.benchmark_id:
        score, ev, _ = scan_text(read_skill(Path("dev_skills") / b)[1], rules)
        rows.append({"benchmark_id": b, "score": score, "rules": " ".join(sorted({e.split("@")[0] for e in ev}))})
    return m.merge(pd.DataFrame(rows), on="benchmark_id")


def summary(d, name):
    mal, ben = d[d.label == 1], d[d.label == 0]
    print(f"{name}: n={len(d)} PR-AUC={pr_auc(d.label, d.score):.3f} "
          f"재현율={(mal.score > 0).mean():.3f} 오탐률={(ben.score > 0).mean():.3f} ({(ben.score > 0).sum()}/{len(ben)})")


def main():
    m = pd.read_csv("runs_dev/scores.csv")
    d = run(m, RULES)
    d.to_csv("runs_dev/s1_v0_samples.csv", index=False)
    hit = lambda rid: d.rules.str.split().apply(lambda xs: rid in xs)

    rows = []
    for r in RULES:
        h = hit(r.id)
        mh, bh = d[h & (d.label == 1)], d[h & (d.label == 0)]
        src = mh.source_id.value_counts()
        n_src = int((src >= MIN_SOURCE_HITS).sum())
        ben_rate = len(bh) / (d.label == 0).sum()
        status = ("결합 전용/제외 검토" if ben_rate > MAX_BENIGN_RATE and not r.requires
                  else "채택" if n_src >= 2 else "출처 편향")
        rows.append({"rule": r.id, "severity": r.severity, "mal_hits": len(mh), "ben_hits": len(bh),
                     "ben_rate": round(ben_rate, 4), "n_sources": n_src,
                     "top_source": f"{src.index[0]} {src.iloc[0] / len(mh):.0%}" if len(mh) else "",
                     "new_vs_baselines": int(((mh.cisco_any == 0) & (mh.skillgate == 0)).sum()), "status": status})
    R = pd.DataFrame(rows)
    R.to_csv("runs_dev/s1_v0_rules.csv", index=False)
    print("== 규칙별 (dev 전체)\n" + R.to_string(index=False))

    print("\n== 전체")
    summary(d, "dev 전체, 규칙 전부")
    biased = set(R[R.status == "출처 편향"].rule)
    if biased:
        summary(run(m, [r for r in RULES if r.id not in biased]), f"dev 전체, 출처 편향 제외 {sorted(biased)}")
    summary(d[d.benchmark_id.isin(pd.read_csv("dev100_labels.csv").benchmark_id)], "dev100")
    fpr = (d[d.label == 0].score > 0).mean()
    print(f"오탐률 기준 {MAX_FPR:.0%}: {'통과' if fpr <= MAX_FPR else '초과 → 정밀도 낮은 규칙부터 뺀다'}")

    print("\n== 출처별 악성 재현율")
    print(d[d.label == 1].groupby("source_id").score.agg(n="count", recall=lambda s: round((s > 0).mean(), 3)).to_string())

    print("\n== Cisco(기본)와 네 칸 (악성)")
    a, c = d.score > 0, d.cisco_any == 1
    mal = d.label == 1
    print(f"정적만 {(a & ~c & mal).sum()}, Cisco만 {(~a & c & mal).sum()}, 둘 다 {(a & c & mal).sum()}, 둘 다 놓침 {(~a & ~c & mal).sum()}")


if __name__ == "__main__":
    main()
