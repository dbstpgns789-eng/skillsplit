# script-only 제외 재현율 추정 (docs/script_only_proposal.md §2.4). 정적·LLM·Jev 공용. 원문은 읽지 않는다.
# 판정이 모두 끝난 시트에만 탐지기 결과를 붙인다.
#   Ŝ = Σ C_h·s_h/n_h,  Ŝ_hit = Σ C_h·s_h,hit/n_h,  제외 재현율 = (H − Ŝ_hit) / (N − Ŝ)
#   H·N은 전체 악성에서 정확히 센 값. 95% 구간은 층 안에서 다시 뽑는 bootstrap(기본 10,000회, seed 0).
# 사용: cd data && python -I script_only_est.py <판정 시트 csv> <정답 csv: benchmark_id,label> <결과 .jsonl> --threshold T [--ge]
#   정적(score > 0):         python -I script_only_est.py ../docs/experiments/script_only_dev_sheet.csv dev_labels.csv ../results/stage1/stage1_v1_dev.jsonl --threshold 0
#   AI 판정기(score ≥ 2/3):  ... <결과 .jsonl> --threshold 0.6667 --ge
import argparse
import json
import sys

import numpy as np
import pandas as pd

VERDICTS = {"text_attack", "script_only", "unclear", "label_noise"}


def estimate(sheet, C, nh):
    so = sheet.verdict == "script_only"
    g = sheet.assign(s=so, sh=so & sheet.hit).groupby("stratum")[["s", "sh"]].sum()
    S = float((C * g.s / nh).sum())
    S_hit = float((C * g.sh / nh).sum())
    return S, S_hit


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sheet")
    ap.add_argument("labels")
    ap.add_argument("results")
    ap.add_argument("--threshold", type=float, required=True)
    ap.add_argument("--ge", action="store_true", help="걸림 = score ≥ threshold (기본은 score > threshold)")
    ap.add_argument("--boot", type=int, default=10_000)
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args()

    sheet = pd.read_csv(a.sheet, dtype={"verdict": str}).fillna({"verdict": ""})
    bad = sheet[~sheet.verdict.isin(VERDICTS)]
    if len(bad):
        raise SystemExit(f"판정이 비었거나 잘못된 행 {len(bad)}개: {list(bad.benchmark_id[:10])}. 판정을 모두 채운 뒤 실행한다")
    lab = pd.read_csv(a.labels)[["benchmark_id", "label"]]
    res = {json.loads(l)["skill_id"]: json.loads(l)["score"] for l in open(a.results, encoding="utf-8") if l.strip()}
    hit = lambda s: (s >= a.threshold) if a.ge else (s > a.threshold)
    mal = lab[lab.label == 1].copy()
    missing = set(mal.benchmark_id) - set(res)
    mal["hit"] = mal.benchmark_id.map(lambda b: hit(res.get(b, 0.0)))
    N, H = len(mal), int(mal.hit.sum())
    if not set(sheet.benchmark_id) <= set(mal.benchmark_id):
        raise SystemExit("시트에 정답의 악성이 아닌 id가 있다. 다른 분할의 시트인지 확인")
    sheet["hit"] = sheet.benchmark_id.map(dict(zip(mal.benchmark_id, mal.hit)))
    dup = sheet.benchmark_id[sheet.benchmark_id.duplicated()]
    if len(dup):
        raise SystemExit(f"시트에 중복 id {len(dup)}개: {list(dup[:10])}")
    if (sheet.groupby("stratum")[["C_h", "n_h"]].nunique() > 1).any(axis=None):
        raise SystemExit("같은 층 안에서 C_h 또는 n_h가 행마다 다르다")
    C = sheet.groupby("stratum").C_h.first()
    nh = sheet.groupby("stratum").size()
    if not (nh == sheet.groupby("stratum").n_h.first()).all():
        raise SystemExit("층별 표본 수가 시트의 n_h와 다르다(행이 빠졌거나 늘었음)")

    S, S_hit = estimate(sheet, C, nh)
    rng = np.random.default_rng(a.seed)
    boot = []
    groups = {h: g for h, g in sheet.groupby("stratum")}
    for _ in range(a.boot):
        bs = pd.concat([g.iloc[rng.integers(0, len(g), len(g))] for g in groups.values()])
        s, sh = estimate(bs, C, nh)
        boot.append(((H - sh) / (N - s), s / C.sum()))
    boot = np.array(boot)
    lo, hi = np.percentile(boot[:, 0], [2.5, 97.5])
    plo, phi = np.percentile(boot[:, 1], [2.5, 97.5])

    vc = sheet.verdict.value_counts().to_dict()
    rule = f"score {'≥' if a.ge else '>'} {a.threshold}"
    print(f"걸림 기준 {rule}. 결과에 없는 악성 {len(missing)}개(안 걸림으로 셈)")
    print(f"전체 기준 재현율: {H}/{N} = {H / N:.3f}")
    print(f"표본 {len(sheet)}개(층 { {k: int(v) for k, v in nh.items()} }, 대상 { {k: int(v) for k, v in C.items()} }), 판정 {vc}")
    print(f"Ŝ(대상 중 script_only 추정) = {S:.1f} / {int(C.sum())} = {S / C.sum():.3f} (95% {plo:.3f}~{phi:.3f}), Ŝ_hit = {S_hit:.1f}")
    print(f"script-only 제외 재현율(추정): ({H} − {S_hit:.1f}) / ({N} − {S:.1f}) = {(H - S_hit) / (N - S):.3f} (95% {lo:.3f}~{hi:.3f}, bootstrap {a.boot}회)")
    print(f"unclear {vc.get('unclear', 0)}/{len(sheet)}개는 분모에 남김")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")  # -I는 PYTHONIOENCODING을 무시하므로 Windows 콘솔(cp949)에서 깨지지 않게
    main()
