# script-only 제외 재현율 추정 (docs/script_only_proposal.md §2.4). 정적·LLM·Jev 공용. 원문은 읽지 않는다.
# 판정이 모두 끝난 시트에만 탐지기 결과를 붙인다.
# 방법(유한모집단 베이즈, 11-10 확정): 후보(동봉 코드가 있는 악성) 전원의 층 h와 걸림 g는 알고 있으므로 칸 (h, g)마다
#   조사 안 한 N_hg − n_hg개 중 script_only 수 ~ Beta-Binomial(N_hg − n_hg, s_hg + a, n_hg − s_hg + a)를 뽑고
#   K1 = 걸림 칸 script_only 합, K = 전체 합으로 제외 재현율 R = (H − K1) / (N − K). H·N은 전체 악성에서 정확히 센 값.
#   대표값은 R 분포의 중앙값, 범위는 95% 베이즈 구간(2.5·97.5 백분위, 10,000회, seed 0). 분모가 0이면 "정의 안 됨".
#   사전분포 a = 0.5(Jeffreys)가 주 결과이고 a = 1(균등)을 같은 판정표로 늘 함께 낸다. 실행 옵션으로 바꾸지 않는다.
# 사용: cd data && python -I script_only_est.py <판정 시트 csv> <후보 csv: script_only.py 출력> <정답 csv: benchmark_id,label> <결과 .jsonl> --threshold T [--ge]
#   정적(score > 0):         python -I script_only_est.py ../docs/experiments/script_only_dev_sheet.csv runs_dev/script_evidence.csv dev_labels.csv ../results/stage1/stage1_v1_dev.jsonl --threshold 0
#   AI 판정기(score ≥ 2/3):  ... <결과 .jsonl> --threshold 0.6667 --ge
import argparse
import json
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # -I는 스크립트 폴더를 import 경로에서 빼므로 직접 넣는다
from script_only_sample import strata

VERDICTS = {"text_attack", "script_only", "unclear", "label_noise"}
PRIORS = {0.5: "주, Jeffreys", 1.0: "민감도, 균등"}
DRAWS, SEED = 10_000, 0


def draw(cells, H, N, a, draws=DRAWS, seed=SEED):
    """cells: [(N_hg, 걸림, n_hg, s_hg)]. 반환: (R 표본(분모 0이면 nan), K 표본)."""
    rng = np.random.default_rng(seed)
    K1, K0 = np.zeros(draws), np.zeros(draws)
    for Nc, g, n, s in cells:
        k = s + rng.binomial(Nc - n, rng.beta(s + a, n - s + a, draws))
        if g:
            K1 += k
        else:
            K0 += k
    den = N - K1 - K0
    return np.where(den > 0, (H - K1) / np.where(den > 0, den, 1), np.nan), K1 + K0


def summary(x):
    ok = x[~np.isnan(x)]
    if len(ok) == 0:
        return "정의 안 됨(분모 0)"
    lo, md, hi = np.percentile(ok, [2.5, 50, 97.5])
    return f"중앙값 {md:.3f} (95% 베이즈 구간 {lo:.3f}~{hi:.3f})" + (f", 분모 0 {np.isnan(x).mean():.1%}" if np.isnan(x).any() else "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sheet")
    ap.add_argument("candidates", help="script_only.py 출력(n_code, source_id). 표본을 뽑은 것과 같은 파일")
    ap.add_argument("labels")
    ap.add_argument("results")
    ap.add_argument("--threshold", type=float, required=True)
    ap.add_argument("--ge", action="store_true", help="걸림 = score ≥ threshold (기본은 score > threshold)")
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
    pool = strata(pd.read_csv(a.candidates))
    if not set(pool.benchmark_id) <= set(mal.benchmark_id):
        raise SystemExit("후보 목록에 정답의 악성이 아닌 id가 있다. 다른 분할의 후보 목록인지 확인")
    pool["hit"] = pool.benchmark_id.map(dict(zip(mal.benchmark_id, mal.hit)))
    if not set(sheet.benchmark_id) <= set(pool.benchmark_id):
        raise SystemExit("시트에 후보가 아닌 id가 있다. 다른 분할의 시트이거나 후보 목록이 다르다")
    dup = sheet.benchmark_id[sheet.benchmark_id.duplicated()]
    if len(dup):
        raise SystemExit(f"시트에 중복 id {len(dup)}개: {list(dup[:10])}")
    if (sheet.groupby("stratum")[["C_h", "n_h"]].nunique() > 1).any(axis=None):
        raise SystemExit("같은 층 안에서 C_h 또는 n_h가 행마다 다르다")
    C = sheet.groupby("stratum").C_h.first()
    nh = sheet.groupby("stratum").size()
    if not (nh == sheet.groupby("stratum").n_h.first()).all():
        raise SystemExit("층별 표본 수가 시트의 n_h와 다르다(행이 빠졌거나 늘었음)")
    if dict(C) != dict(pool.stratum.value_counts()) or \
            not (sheet.stratum.values == sheet.benchmark_id.map(dict(zip(pool.benchmark_id, pool.stratum))).values).all():
        raise SystemExit("시트의 층·C_h가 후보 목록과 다르다. 표본을 뽑은 것과 같은 후보 목록인지 확인")

    sheet = sheet.merge(pool[["benchmark_id", "hit"]], on="benchmark_id")
    cells, names = [], []
    for h in C.index:
        for g in (True, False):
            sub = sheet[(sheet.stratum == h) & (sheet.hit == g)]
            cells.append((int(((pool.stratum == h) & (pool.hit == g)).sum()), g, len(sub), int((sub.verdict == "script_only").sum())))
            names.append(f"({h}, {'걸림' if g else '안 걸림'})")

    vc = sheet.verdict.value_counts().to_dict()
    rule = f"score {'≥' if a.ge else '>'} {a.threshold}"
    print(f"걸림 기준 {rule}. 결과에 없는 악성 {len(missing)}개(안 걸림으로 셈)")
    print(f"전체 기준 재현율: {H}/{N} = {H / N:.3f}")
    print(f"표본 {len(sheet)}개(층 { {k: int(v) for k, v in nh.items()} }, 대상 { {k: int(v) for k, v in C.items()} }), 판정 {vc}")
    print("칸(층, 걸림) 후보 수/표본/표본 script_only: " + ", ".join(f"{m} {Nc}/{n}/{s}" for m, (Nc, g, n, s) in zip(names, cells)))
    for pa, name in PRIORS.items():
        R, K = draw(cells, H, N, pa)
        print(f"[a={pa:g}, {name}] 대상 중 script_only 비율: {summary(K / C.sum())}")
        print(f"[a={pa:g}, {name}] script-only 제외 재현율(표본 추정, 보조): {summary(R)}")
    print(f"유한모집단 베이즈, {DRAWS}회, seed {SEED}. unclear {vc.get('unclear', 0)}/{len(sheet)}개는 script_only가 아니므로 분모에 남김")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")  # -I는 PYTHONIOENCODING을 무시하므로 Windows 콘솔(cp949)에서 깨지지 않게
    sys.stderr.reconfigure(encoding="utf-8")  # 멈출 때 내는 한글 안내도 같은 이유
    main()
