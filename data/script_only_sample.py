# script-only 판정 표본 추출 + 판정 시트 (docs/script_only_proposal.md §2.2). 탐지기 결과는 쓰지 않는다. 원문은 출력하지 않는다.
# 대상: 동봉 코드 파일이 있는 악성(script_only.py 출력의 n_code > 0).
# 층: 대상이 100개 이상인 출처는 단독 층, 나머지는 "기타" 한 층. 배분: 비례(최대 나머지) 후 층당 최소 2(가장 큰 층에서 덜어냄).
# 사용: cd data && python -I script_only_sample.py <script_evidence csv> <n> <출력 시트 csv> [--seed 0]
#   dev:  python -I script_only_sample.py runs_dev/script_evidence.csv 30 ../docs/experiments/script_only_dev_sheet.csv
#   test: python -I script_only_sample.py <test script_evidence csv> 100 <test 시트 csv>
import argparse
import os
import sys
import tarfile

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # -I는 스크립트 폴더를 import 경로에서 빼므로 직접 넣는다
from script_only import is_code

BIG, MIN_H = 100, 2


def strata(ev):
    pool = ev[ev.n_code > 0].copy()
    size = pool.source_id.value_counts()
    pool["stratum"] = pool.source_id.where(pool.source_id.map(size) >= BIG, "기타")
    return pool


def allocate(C, n):
    """C: 층 → 대상 수. 비례 배분(최대 나머지) 후 층당 최소 MIN_H."""
    q = C / C.sum() * n
    a = q.astype(int)
    for h in (q - a).sort_values(ascending=False).index[: n - a.sum()]:
        a[h] += 1
    for h in a.index:
        need = min(MIN_H, C[h]) - a[h]
        while need > 0:
            big = a.drop(h).idxmax()
            a[big] -= 1
            a[h] += 1
            need -= 1
    return a


def code_files(ids):
    """benchmark_id → (코드 파일 목록, SKILL.md가 이름을 부르는 파일 목록). 이름만 본다."""
    m = pd.read_csv("package_manifest.csv").set_index("benchmark_id").loc[list(ids)]
    out = {}
    for arc, g in m.groupby("package_archive"):
        roots = dict(zip(g.package_relative_path, g.index))
        files, skill, depth = {}, {}, {}
        with tarfile.open(arc) as t:
            for mem in t:
                if not mem.isfile():
                    continue
                root = next((r for r in roots if mem.name.startswith(r + "/")), None)
                if root is None:
                    continue
                bid, rel = roots[root], mem.name[len(root) + 1:]
                data = t.extractfile(mem).read()
                if os.path.basename(rel).lower() == "skill.md":
                    if rel.count("/") < depth.get(bid, 99):
                        skill[bid], depth[bid] = data.decode("utf-8", "ignore"), rel.count("/")
                elif is_code(rel, data[:2]):
                    files.setdefault(bid, []).append(rel)
        for bid in g.index:
            fs = sorted(files.get(bid, []))
            out[bid] = (fs, [f for f in fs if os.path.basename(f) in skill.get(bid, "")])
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("evidence")
    ap.add_argument("n", type=int)
    ap.add_argument("out")
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args()

    pool = strata(pd.read_csv(a.evidence))
    C = pool.stratum.value_counts().sort_index()
    nh = allocate(C, a.n)
    s = pd.concat([pool[pool.stratum == h].sample(int(nh[h]), random_state=a.seed) for h in C.index])
    s["C_h"], s["n_h"] = s.stratum.map(C), s.stratum.map(nh)
    cf = code_files(s.benchmark_id)
    s["code_files"] = s.benchmark_id.map(lambda b: "; ".join(cf[b][0]))
    s["named_in_skill"] = s.benchmark_id.map(lambda b: "; ".join(cf[b][1]))
    s["auto_evidence"] = s.evidence.fillna("")
    for c in ("verdict", "code_evidence", "skill_evidence", "judge", "note"):
        s[c] = ""
    cols = ["benchmark_id", "stratum", "C_h", "n_h", "n_code", "code_files", "named_in_skill", "auto_evidence",
            "verdict", "code_evidence", "skill_evidence", "judge", "note"]
    s[cols].to_csv(a.out, index=False, encoding="utf-8-sig")
    print(f"대상 {len(pool)}개, 층 { {k: int(v) for k, v in C.items()} }, 배분 { {k: int(v) for k, v in nh.items()} }, 표본 {len(s)}개 → {a.out}")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")  # -I는 PYTHONIOENCODING을 무시하므로 Windows 콘솔(cp949)에서 깨지지 않게
    main()
