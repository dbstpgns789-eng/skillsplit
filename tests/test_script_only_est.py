"""script-only 제외 재현율 추정기(data/script_only_est.py)의 가상 사례 (PR #9 리뷰 2번).

cells = [(칸 후보 수 N_hg, 걸림, 칸 표본 수 n_hg, 표본 script_only 수 s_hg)]. 실제 판정·원문은 쓰지 않는다.
"""
import json
import os
import subprocess
import sys

import numpy as np
import pytest

DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
sys.path.insert(0, DATA)
import script_only_est as est  # noqa: E402

A = [0.5, 1.0]


@pytest.mark.parametrize("a", A)
def test_zero_observed_still_leaves_uncertainty(a):
    # 50개 중 5개만 조사했고 표본에 script_only 0개 → 조사 안 한 45개 몫의 불확실성이 남아야 한다
    R, K = est.draw([(30, True, 5, 0), (20, False, 0, 0)], H=60, N=100, a=a)
    lo, hi = np.percentile(R, [2.5, 97.5])
    assert hi - lo > 0.05 and np.percentile(K, 97.5) > 0


@pytest.mark.parametrize("a", A)
def test_small_data_stays_in_0_1(a):
    # 예전 bootstrap은 −1.600~0.480이 나온 자료. 자르지 않아도 [0, 1] 안
    R, _ = est.draw([(10, True, 1, 1), (10, False, 1, 0)], H=12, N=25, a=a)
    assert R.min() >= 0 and R.max() <= 1


@pytest.mark.parametrize("a", A)
def test_census_has_no_sampling_uncertainty(a):
    # 전수조사: 참값 (15 − 1) / (30 − 2) = 0.5 한 점
    R, K = est.draw([(2, True, 2, 1), (2, False, 2, 1)], H=15, N=30, a=a)
    assert np.all(R == 0.5) and np.all(K == 2)


@pytest.mark.parametrize("a", A)
def test_zero_denominator_is_undefined(a):
    R, _ = est.draw([(3, True, 3, 3)], H=3, N=3, a=a)
    assert np.isnan(R).all() and est.summary(R) == "정의 안 됨(분모 0)"


def test_summary_reports_median_and_bayes_interval():
    assert est.summary(np.array([0.5] * 10)) == "중앙값 0.500 (95% 베이즈 구간 0.500~0.500)"


# ---- 실행 전체: 판정표 + 후보 목록 + 정답 + 결과를 이어 붙인다 ----
# 악성 M1~M6(M1~M4가 후보, 한 출처라 "기타" 층), 정상 B1. 걸림: M1·M2·M5 → H=3, N=6
# 전수조사 판정: M1 script_only(걸림), M3 script_only(안 걸림) → R = (3 − 1) / (6 − 2) = 0.5

def write_inputs(tmp_path, sheet_rows):
    (tmp_path / "cand.csv").write_text(
        "benchmark_id,source_id,n_code\n" + "".join(f"M{i},S1,{1 if i <= 4 else 0}\n" for i in range(1, 7)), encoding="utf-8")
    (tmp_path / "labels.csv").write_text(
        "benchmark_id,label\n" + "".join(f"M{i},1\n" for i in range(1, 7)) + "B1,0\n", encoding="utf-8")
    scores = {"M1": 0.9, "M2": 0.5, "M3": 0, "M4": 0, "M5": 0.3, "M6": 0, "B1": 0}
    (tmp_path / "res.jsonl").write_text(
        "".join(json.dumps({"skill_id": k, "score": v, "evidence": []}) + "\n" for k, v in scores.items()), encoding="utf-8")
    (tmp_path / "sheet.csv").write_text(
        "benchmark_id,stratum,C_h,n_h,verdict\n" + "".join(",".join(map(str, r)) + "\n" for r in sheet_rows), encoding="utf-8")
    return [str(tmp_path / f) for f in ("sheet.csv", "cand.csv", "labels.csv", "res.jsonl")]


def run(args):
    return subprocess.run([sys.executable, "-I", os.path.join(DATA, "script_only_est.py"), *args, "--threshold", "0"],
                          capture_output=True, text=True, encoding="utf-8")


CENSUS = [("M1", "기타", 4, 4, "script_only"), ("M2", "기타", 4, 4, "text_attack"),
          ("M3", "기타", 4, 4, "script_only"), ("M4", "기타", 4, 4, "unclear")]


def test_cli_census_reports_both_priors(tmp_path):
    p = run(write_inputs(tmp_path, CENSUS))
    assert p.returncode == 0, p.stderr
    assert "전체 기준 재현율: 3/6 = 0.500" in p.stdout
    for a in ("a=0.5", "a=1"):
        line = next(l for l in p.stdout.splitlines() if "제외 재현율" in l and a in l)
        assert "중앙값 0.500 (95% 베이즈 구간 0.500~0.500)" in line


@pytest.mark.parametrize("rows, msg", [
    ([*CENSUS[:3], ("M3", "기타", 4, 4, "unclear")], "중복 id"),
    ([(b, h, 5, n, v) for b, h, C, n, v in CENSUS], "후보 목록"),          # C_h가 후보 수(4)와 다름
    ([(b, "SRC9", C, n, v) for b, h, C, n, v in CENSUS], "후보 목록"),     # 층 이름이 후보 목록과 다름
    ([*CENSUS[:3], ("M5", "기타", 4, 4, "unclear")], "후보가 아닌 id"),     # M5는 코드 파일이 없는 악성
])
def test_cli_rejects_sheet_not_matching_candidates(tmp_path, rows, msg):
    p = run(write_inputs(tmp_path, rows))
    assert p.returncode != 0 and msg in p.stderr
