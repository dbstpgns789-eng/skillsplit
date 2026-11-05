# RUN_CMD·RUN_INIT가 걸린 줄이 "반복된 문장 틀"인지 출처와 무관하게 센다(E6 §3).
# 걸린 줄을 정규화(백틱 안·경로·파일 이름·숫자를 자리표시자로, 소문자, 기호 제거)한다.
# 빈칸 단어만 바뀌는 틀이 있어서, 정규화 문장끼리 단어 3-gram 자카드 ≥ NEAR이면 "거의 같은 문장"으로 본다.
# 걸린 문장과 거의 같은 문장이 (자기 포함) MIN_REPEAT개 이상 샘플에 나오면 "반복 틀". 출처는 기준에 쓰지 않고 집계에만 쓴다.
# 앞부분만 같고 뒤가 다른 긴 줄이 있어서, "걸린 위치부터 WIN단어"가 같은 샘플 수도 센다(주 기준, E6 §3).
# 원문은 출력하지 않는다(정규화 문장 앞 90자만).
# 사용: cd data && python run_template.py → runs_dev/run_template.csv
import re
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from skillsplit.stage1.rules import RULES
from skillsplit.stage1.scan import segment
from skillsplit.stage2.common import read_skill

MIN_REPEAT = 10
NEAR = 0.6
WIN = 8
BY = {r.id: r for r in RULES}


def norm(line):
    s = re.sub(r"`[^`]*`", " <cmd> ", line.lower())
    s = re.sub(r"(?:[\w.~-]*/)+[\w.-]+|\b[\w-]+\.(?:py|sh|js|ts|ps1|md|json|txt)\b", " <path> ", s)
    s = re.sub(r"\d+", " <n> ", s)
    s = re.sub(r"[^a-z<> ]+", " ", s)
    return re.sub(r"\s+", " ", s).strip()


def hits(d):
    rows = []
    for b, lab, src, rs in zip(d.benchmark_id, d.label, d.source_id, d.rules):
        for rid in ("RUN_CMD", "RUN_INIT"):
            if rid not in rs.split():
                continue
            v = segment(read_skill(Path("dev_skills") / b)[1][:300_000])["prose"]
            for m in BY[rid].pattern.finditer(v):
                s, e = v.rfind("\n", 0, m.start()) + 1, v.find("\n", m.end())
                rows.append({"benchmark_id": b, "label": lab, "source_id": src, "rule": rid,
                             "line": v.count("\n", 0, m.start()) + 1, "form": norm(v[s: e if e >= 0 else None]),
                             "win": " ".join(norm(v[m.start(): m.start() + 300]).split()[:WIN])})
    return pd.DataFrame(rows)


def near_counts(R):
    """정규화 문장마다, 자카드 ≥ NEAR인 문장(자기 포함)을 가진 샘플 수."""
    samples = R.groupby("form").benchmark_id.apply(set)
    forms = list(samples.index)
    grams = [set(zip(w, w[1:], w[2:])) or {tuple(w)} for w in (f.split() for f in forms)]
    out = {}
    for i, gi in enumerate(grams):
        u = set()
        for j, gj in enumerate(grams):
            if len(gi & gj) >= NEAR * len(gi | gj):
                u |= samples.iloc[j]
        out[forms[i]] = len(u)
    return pd.Series(out)


def main():
    d = pd.read_csv("runs_dev/s1_v1_samples.csv").fillna({"rules": ""})
    R = hits(d)
    exact = R.groupby("form").benchmark_id.nunique()
    near = near_counts(R)
    R["exact_samples"], R["near_samples"] = R.form.map(exact), R.form.map(near)
    R["win_samples"] = R.win.map(R.groupby("win").benchmark_id.nunique())
    R["form_id"] = R.form.map({f: i for i, f in enumerate(near.sort_values(ascending=False).index)})
    R.drop(columns=["form", "win"]).to_csv("runs_dev/run_template.csv", index=False)

    per = R.groupby(["benchmark_id", "source_id", "rule"])[["win_samples", "exact_samples", "near_samples"]].max().reset_index()
    print(f"악성 적중 샘플×규칙 {len(per)}, 걸린 줄 {len(R)}, 서로 다른 정규화 문장 {len(exact)}")
    for col, name in [("win_samples", f"걸린 위치부터 {WIN}단어 같음(주 기준)"), ("exact_samples", "줄 전체 완전 일치"),
                      ("near_samples", f"줄 전체 거의 같음(자카드 ≥ {NEAR})")]:
        per["kind"] = (per[col] >= MIN_REPEAT).map({True: "반복 틀", False: "그 외"})
        print(f"\n== {name}: 걸린 줄 중 하나라도 같은 문장이 {MIN_REPEAT}개 이상 샘플에 나오면 반복 틀")
        print(per.pivot_table(index=["rule", "kind"], columns="source_id", values="benchmark_id",
                              aggfunc="count", fill_value=0).to_string())
    print("\n== 정규화 문장 하나와 거의 같은 문장이 나오는 샘플 수의 분포 (문장 수)")
    print(pd.cut(near, [0, 1, 2, 9, 99, 10**6], labels=["1", "2", "3-9", "10-99", "100+"]).value_counts().sort_index().to_string())
    print("\n== 거의 같은 문장이 가장 많은 10개 (form_id, 샘플 수, 출처, 앞 90자)")
    for f in near.sort_values(ascending=False).index[:10]:
        g = R[R.form == f]
        print(f"#{g.form_id.iloc[0]:<4} {near[f]:5d} {g.source_id.value_counts().to_dict()}  {f[:90]}")


if __name__ == "__main__":
    main()
