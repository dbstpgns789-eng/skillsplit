# script-only 제외 재현율 95% 구간 계산 방법 비교 기록 (PR #9 리뷰 2번). 11-10에 유한모집단 베이즈로 정해 script_only_est.py에 반영했다.
# 이 파일은 그 근거(리뷰 가상 사례 4개, 예전 bootstrap과의 coverage 비교)를 다시 내는 용도이고 test 순서에는 쓰지 않는다.
# 새 방법(draw, summary)은 script_only_est.py의 것을 그대로 불러 쓴다. a=0.5(Jeffreys).
# 출력: ① 리뷰의 가상 사례 4개, ② coverage(가상 모집단에서 95% 구간이 참값을 포함하는 비율, 새 방법 vs 예전 bootstrap)
#   coverage의 후보 칸 크기·H·N은 dev 값(script_evidence_dev.csv의 n_code > 0 × stage1_v1_dev.jsonl score > 0)을 적어 둔 것. 원문·실제 판정은 쓰지 않는다
# 사용: cd data && python -I script_only_ci_trial.py   (약 1분 30초, 시드 고정)
import os
import sys

import numpy as np


sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # -I는 스크립트 폴더를 import 경로에서 빼므로 직접 넣는다
from script_only_est import draw, summary


def polya(cells, H, N, draws=10_000, seed=0):
    return draw(cells, H, N, a=0.5, draws=draws, seed=seed)[0]


def old_boot(strata, H, N, B, rng):
    """11-09까지 script_only_est.py가 쓰던 층화 bootstrap. strata: [(C_h, s array, sh array)]"""
    out = np.empty(B)
    for b in range(B):
        S = Sh = 0.0
        for C, s, sh in strata:
            i = rng.integers(0, len(s), len(s))
            S += C * s[i].mean(); Sh += C * sh[i].mean()
        out[b] = (H - Sh) / (N - S) if N - S else np.nan
    return out


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    print("== 리뷰 가상 사례 (cells = (후보 수, 걸림, 표본, script_only))")
    cases = {
        "(a) 50개 중 5개 조사, script_only 0": ([(30, True, 5, 0), (20, False, 0, 0)], 60, 100),
        "(b) C=20, n=2, H=12":               ([(10, True, 1, 1), (10, False, 1, 0)], 12, 25),
        "(c) 전수조사 C=n=4":                 ([(2, True, 2, 1), (2, False, 2, 1)], 15, 30),
        "(d) 모든 악성이 script_only":         ([(3, True, 3, 3)], 3, 3),
    }
    for k, (cells, H, N) in cases.items():
        print(f"{k}: {summary(polya(cells, H, N))}")
    print("   (c) 참값: (15−1)/(30−2) = 0.500")

    print("\n== coverage: dev 구조 가상 모집단(후보 칸 크기·H·N은 dev 값), 설계대로 층화 표본 → 95% 구간이 참값을 포함하는 비율")
    cand = {("SRC001", True): 503, ("SRC001", False): 1218, ("SRC010", True): 2012, ("SRC010", False): 584,
            ("기타", True): 12, ("기타", False): 161}
    H, N = 3653, 6658
    alloc = {100: {"SRC001": 38, "SRC010": 58, "기타": 4}, 30: {"SRC001": 12, "SRC010": 16, "기타": 2}}
    scen = {"보통(걸림 10%, 안 걸림 35%)": {True: .10, False: .35},
            "드묾(걸림 1%, 안 걸림 2%)": {True: .01, False: .02},
            "많음(걸림 40%, 안 걸림 70%)": {True: .40, False: .70}}
    rng = np.random.default_rng(1)
    REPS = 400
    for sname, rate in scen.items():
        for n, al in alloc.items():
            cov_p = cov_b = 0; wid_p = []; wid_b = []; neg_b = 0
            for _ in range(REPS):
                pop = {}
                for (h, g), Nc in cand.items():
                    pop[(h, g)] = rng.random(Nc) < rate[g]
                K1 = sum(v.sum() for (h, g), v in pop.items() if g)
                K = sum(v.sum() for v in pop.values())
                truth = (H - K1) / (N - K)
                cells, strata_old = [], []
                for h, nh in al.items():
                    units = np.concatenate([np.c_[pop[(h, g)], np.full(cand[(h, g)], g)] for g in (True, False)])
                    pick = units[rng.choice(len(units), nh, replace=False)]
                    for g in (True, False):
                        m = pick[:, 1] == g
                        cells.append((cand[(h, g)], g, int(m.sum()), int(pick[m, 0].sum())))
                    strata_old.append((len(units), pick[:, 0].astype(float), (pick[:, 0] * pick[:, 1]).astype(float)))
                R = polya(cells, H, N, draws=2000, seed=int(rng.integers(1 << 30)))
                lo, hi = np.percentile(R, [2.5, 97.5]); cov_p += lo <= truth <= hi; wid_p.append(hi - lo)
                Rb = old_boot(strata_old, H, N, 500, rng)
                lo, hi = np.nanpercentile(Rb, [2.5, 97.5]); cov_b += lo <= truth <= hi; wid_b.append(hi - lo); neg_b += lo < 0
            print(f"{sname:28s} n={n:3d}  새 방식 {cov_p / REPS:.1%} (폭 {np.mean(wid_p):.3f})   예전 bootstrap {cov_b / REPS:.1%} (폭 {np.mean(wid_b):.3f})")
