# [시험용, 미확정] script-only 제외 재현율 95% 구간 계산 방법 비교 (PR #9 리뷰 2번, 세훈 님 검토용).
# script_only_est.py와 동결 문서의 test 순서는 이 파일을 쓰지 않는다. 방법이 정해지면 script_only_est.py에 반영한다.
# 초안: 층 h × 탐지기 걸림 g 칸마다 후보 수 N_hg는 정확히 알고, 표본 n_hg 중 script_only가 s_hg개.
#   조사 안 한 U = N_hg − n_hg개 중 script_only 수 ~ Beta-Binomial(U, s+a, n−s+a)  (유한모집단 베이즈, a=0.5 Jeffreys)
#   K1 = Σ_h K_h,걸림, K0 = Σ_h K_h,안걸림 →  R = (H − K1) / (N − K1 − K0). 분모 0이면 "정의 안 됨"
# 출력: ① 리뷰의 가상 사례 4개, ② coverage(가상 모집단에서 95% 구간이 참값을 포함하는 비율, 초안 vs 현재 bootstrap)
#   coverage의 후보 칸 크기·H·N은 dev 값(script_evidence_dev.csv의 n_code > 0 × stage1_v1_dev.jsonl score > 0)을 적어 둔 것. 원문·실제 판정은 쓰지 않는다
# 사용: cd data && python -I script_only_ci_trial.py   (약 1분 30초, 시드 고정)
import numpy as np


def polya(cells, H, N, draws=10_000, a=0.5, seed=0):
    """cells: [(N_hg, hit: bool, n_hg, s_hg)]. 반환: R 표본(분모 0이면 nan)."""
    rng = np.random.default_rng(seed)
    K1, K0 = np.zeros(draws), np.zeros(draws)
    for Nc, g, n, s in cells:
        p = rng.beta(s + a, n - s + a, draws)
        k = s + rng.binomial(Nc - n, p)
        if g:
            K1 += k
        else:
            K0 += k
    den = N - K1 - K0
    return np.where(den > 0, (H - K1) / np.where(den > 0, den, 1), np.nan)


def summarize(R):
    ok = R[~np.isnan(R)]
    if len(ok) == 0:
        return "정의 안 됨(분모 0)"
    lo, md, hi = np.percentile(ok, [2.5, 50, 97.5])
    return f"중앙 {md:.3f}, 95% {lo:.3f}~{hi:.3f}" + (f", 분모 0 {np.isnan(R).mean():.1%}" if np.isnan(R).any() else "")


def old_boot(strata, H, N, B, rng):
    """현재 script_only_est.py와 같은 방식. strata: [(C_h, s array, sh array)]"""
    out = np.empty(B)
    for b in range(B):
        S = Sh = 0.0
        for C, s, sh in strata:
            i = rng.integers(0, len(s), len(s))
            S += C * s[i].mean(); Sh += C * sh[i].mean()
        out[b] = (H - Sh) / (N - S) if N - S else np.nan
    return out


if __name__ == "__main__":
    import sys
    sys.stdout.reconfigure(encoding="utf-8")
    print("== 리뷰 가상 사례 (cells = (후보 수, 걸림, 표본, script_only))")
    cases = {
        "(a) 50개 중 5개 조사, script_only 0": ([(30, True, 5, 0), (20, False, 0, 0)], 60, 100),
        "(b) C=20, n=2, H=12":               ([(10, True, 1, 1), (10, False, 1, 0)], 12, 25),
        "(c) 전수조사 C=n=4":                 ([(2, True, 2, 1), (2, False, 2, 1)], 15, 30),
        "(d) 모든 악성이 script_only":         ([(3, True, 3, 3)], 3, 3),
    }
    for k, (cells, H, N) in cases.items():
        print(f"{k}: {summarize(polya(cells, H, N))}")
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
            print(f"{sname:28s} n={n:3d}  새 방식 {cov_p / REPS:.1%} (폭 {np.mean(wid_p):.3f})   현재 bootstrap {cov_b / REPS:.1%} (폭 {np.mean(wid_b):.3f})")
