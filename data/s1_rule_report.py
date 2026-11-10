# 정적 탐지기 규칙 채택 보고서 (skillsplit/stage1/README.md §4). dev 전체에 돌려 규칙별·전체 수치를 낸다. 원문은 출력하지 않는다.
# 필요: dev_skills/(make_dev.py), runs_dev/scores.csv(E1), dev100_labels.csv(sample.py)
# 사용: cd data && python s1_rule_report.py → runs_dev/s1_{TAG}_rules.csv, runs_dev/s1_{TAG}_samples.csv
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from skillsplit.stage1.rules import RULES
from skillsplit.stage1.scan import scan_text
from skillsplit.stage2.common import read_skill

MIN_SOURCE_HITS = 3   # 출처 하나로 셀 최소 악성 적중 수
MAX_BENIGN_RATE = 0.01
MAX_TOP_SHARE = 0.9    # 악성 적중의 이 비율 이상이 한 출처면 출처 편향 (4주차 추가, E6)
MAX_FPR = 0.02
TAG = "v1"  # 출력 파일 이름. v0 결과(E5)는 커밋 aaa35f7에서 TAG 없이 s1_v0_*


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
    print(f"{name}: n={len(d)} PR-AUC={pr_auc(d.label, d.score):.3f} (전부 0점이면 {d.label.mean():.3f}) "
          f"재현율={(mal.score > 0).mean():.3f} 오탐률={(ben.score > 0).mean():.3f} ({(ben.score > 0).sum()}/{len(ben)})")


def equal_weight_score(rules_str):
    """걸린 규칙(evidence에 남은 것)마다 가중치를 모두 0.7로 같게 한 noisy-OR. 가중치 차이가 순위에 주는 영향 확인용."""
    return 1 - 0.3 ** len(rules_str.split())


def main():
    m = pd.read_csv("runs_dev/scores.csv")
    d = run(m, RULES)
    d.to_csv(f"runs_dev/s1_{TAG}_samples.csv", index=False)
    hit = lambda rid: d.rules.str.split().apply(lambda xs: rid in xs)

    rows = []
    for r in RULES:
        h = hit(r.id)
        mh, bh = d[h & (d.label == 1)], d[h & (d.label == 0)]
        src = mh.source_id.value_counts()
        n_src = int((src >= MIN_SOURCE_HITS).sum())
        ben_rate = len(bh) / (d.label == 0).sum()
        top_share = src.iloc[0] / len(mh) if len(mh) else 0
        status = ("결합 전용/제외 검토" if ben_rate > MAX_BENIGN_RATE and not r.requires
                  else "채택" if n_src >= 2 and top_share < MAX_TOP_SHARE else "출처 편향")
        rows.append({"rule": r.id, "severity": r.severity, "mal_hits": len(mh), "ben_hits": len(bh),
                     "ben_rate": round(ben_rate, 4), "n_sources": n_src,
                     "top_source": f"{src.index[0]} {top_share:.0%}" if len(mh) else "",
                     "new_vs_baselines": int(((mh.cisco_any == 0) & (mh.skillgate == 0)).sum()), "status": status})
    R = pd.DataFrame(rows)
    R.to_csv(f"runs_dev/s1_{TAG}_rules.csv", index=False)
    print("== 규칙별 (dev 전체)\n" + R.to_string(index=False))

    print("\n== 전체")
    summary(d, "dev 전체, 규칙 전부")
    biased = set(R[R.status == "출처 편향"].rule)
    nb = run(m, [r for r in RULES if r.id not in biased])
    summary(nb, f"dev 전체, 출처 편향 제외 {sorted(biased)}")
    in100 = d.benchmark_id.isin(pd.read_csv("dev100_labels.csv").benchmark_id)
    summary(d[in100], "dev100")
    eq = d.rules.fillna("").apply(equal_weight_score)
    print(f"가중치 모두 같게(0.7): PR-AUC dev 전체 {pr_auc(d.label, eq):.4f} (지금 {pr_auc(d.label, d.score):.4f}), "
          f"dev100 {pr_auc(d.label[in100], eq[in100]):.4f} (지금 {pr_auc(d.label[in100], d.score[in100]):.4f})")
    fpr = (d[d.label == 0].score > 0).mean()
    print(f"오탐률 기준 {MAX_FPR:.0%}: {'통과' if fpr <= MAX_FPR else '초과 → 정밀도 낮은 규칙부터 뺀다'}")

    print("\n== 출처별 악성 재현율")
    rec = lambda x: x[x.label == 1].groupby("source_id").score.agg(n="count", recall=lambda s: round((s > 0).mean(), 3))
    print(rec(d).join(rec(nb).recall.rename("recall_편향제외")).to_string())

    print("\n== Cisco(기본)와 네 칸 (악성)")
    a, c = d.score > 0, d.cisco_any == 1
    mal = d.label == 1
    print(f"정적만 {(a & ~c & mal).sum()}, Cisco만 {(~a & c & mal).sum()}, 둘 다 {(a & c & mal).sum()}, 둘 다 놓침 {(~a & ~c & mal).sum()}")


if __name__ == "__main__":
    main()
