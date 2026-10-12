# E4: 두 도구가 놓친 SRC001 중 E3 신호(marker·지시 신호·op_heading)가 하나도 없는 539개를 고르고,
# 같은 바탕 글을 쓴 다른 dev 샘플과 문단 단위로 비교한다. 원문은 출력하지 않는다.
# 필요: runs_dev/scores.csv(E1), runs_dev/src001_signals.csv(E3)
# → runs_dev/e4_residual.csv(539개), runs_dev/e4_diff.csv, runs_dev/e4_pairs.csv(기준 샘플이 있는 것)
import re, hashlib, collections, pandas as pd

sc = pd.read_csv("runs_dev/scores.csv")
m = sc.merge(pd.read_csv("runs_dev/src001_signals.csv"), on="benchmark_id")
x = m[(m.source_id == "SRC001") & (m.cisco_any == 0) & (m.skillgate == 0)]
res = x[~x[["marker", "init_directive", "operates_under", "prompt_leak", "op_heading"]].any(axis=1)]
res[["benchmark_id"]].to_csv("runs_dev/e4_residual.csv", index=False)
print("대상:", len(res))

def paras(b):
    t = open(f"dev_skills/{b}/SKILL.md", encoding="utf-8").read()[:300000]
    out = []
    for p in re.split(r"\n\s*\n", t):
        n = re.sub(r"\s+", " ", p).strip().lower()
        if len(n) >= 40:
            out.append(hashlib.md5(n.encode()).hexdigest())
    return out

P = {b: set(paras(b)) for b in sc.benchmark_id}
idx = collections.defaultdict(set)
for b, ps in P.items():
    for h in ps:
        idx[h].add(b)
lab = dict(zip(sc.benchmark_id, sc.label))
caught = dict(zip(sc.benchmark_id, (sc.cisco_any == 1) | (sc.skillgate == 1)))

rows = []
for b in sorted(res.benchmark_id):
    c = collections.Counter(o for h in P[b] for o in idx[h] if o != b)
    ref, shared = c.most_common(1)[0] if c else (None, 0)
    rows.append({"benchmark_id": b, "n_para": len(P[b]), "ref": ref, "ref_label": lab.get(ref), "shared_with_ref": shared,
                 "unique_para": sum(len(idx[h]) == 1 for h in P[b])})  # dev 전체에서 이 샘플에만 있는 문단
d = pd.DataFrame(rows)
d.to_csv("runs_dev/e4_diff.csv", index=False)

p = d[d.shared_with_ref >= 3].copy()
p["x_not_in_ref"] = [len(P[b] - P[r]) for b, r in zip(p.benchmark_id, p.ref)]
p["ref_not_in_x"] = [len(P[r] - P[b]) for b, r in zip(p.benchmark_id, p.ref)]
p["ref_caught"] = [int(caught[r]) for r in p.ref]
p.to_csv("runs_dev/e4_pairs.csv", index=False)
print(f"바탕 글을 공유하는 dev 샘플(공유 문단 3개 이상)이 있는 것: {len(p)}, 기준 라벨 {p.ref_label.value_counts().to_dict()}")
print(f"기준 대비 추가 문단 1~2개: {p.x_not_in_ref.between(1, 2).sum()}, 0개: {(p.x_not_in_ref == 0).sum()}")
fam = pd.read_csv("skills.csv", usecols=["benchmark_id", "label", "structural_family_id"])
f = fam[fam.benchmark_id.isin(res.benchmark_id)].structural_family_id.dropna().unique()
print(f"structural_family {len(f)}종 중 정상을 포함한 묶음:", fam[fam.structural_family_id.isin(f) & (fam.label == 0)].structural_family_id.nunique())
