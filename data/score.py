# Cisco(정적, LLM 끔)와 SkillGate(규칙만) 결과를 채점하고 샘플별 표(scores.csv)를 남긴다.
# 실행: python score.py dev_labels.csv runs_dev
# 먼저: skill-scanner scan-all dev_skills --format json --output runs_dev/cisco.json
#       .venv-skillgate/Scripts/python run_skillgate.py dev_skills runs_dev/skillgate.json
import json, sys, pandas as pd

labels, run = sys.argv[1], sys.argv[2]
lab = pd.read_csv(labels)
cs = json.load(open(f"{run}/cisco.json", encoding="utf-8"))["results"]
cs = pd.DataFrame([{"benchmark_id": x["skill_path"].replace("\\", "/").rstrip("/").split("/")[-1].upper(),
                    "cisco_any": int(not x["is_safe"]),                                # count_cisco.py 기준
                    "cisco_high": int(x["max_severity"] in ("HIGH", "CRITICAL")),      # 논문 기준
                    "cisco_rules": " ".join(sorted({f["rule_id"] for f in x["findings"]}))} for x in cs])
sg = pd.DataFrame(json.load(open(f"{run}/skillgate.json", encoding="utf-8")))
sg = sg.rename(columns={"flag": "skillgate"}).assign(skillgate_rules=sg["rules"].map(lambda r: " ".join(sorted(set(r)))))
m = lab.merge(cs, on="benchmark_id", how="left").merge(sg[["benchmark_id", "skillgate", "skillgate_rules"]], on="benchmark_id", how="left")
tools = ["cisco_any", "cisco_high", "skillgate"]

def macro_f1(y, p):  # MaliciousSkillBench 논문 주지표 = 악성 F1과 정상 F1의 평균
    f = lambda pos: 2 * ((y == pos) & (p == pos)).sum() / max((y == pos).sum() + (p == pos).sum(), 1)
    return (f(1) + f(0)) / 2

print("스캔 실패(지표에서 제외):", m[tools].isna().sum().to_dict())
for c in tools:
    ok = m[m[c].notna()]
    mal, ben = ok[ok.label == 1][c], ok[ok.label == 0][c]
    print(f"{c:11s} Macro-F1 {macro_f1(ok.label, ok[c]):.3f}  악성 재현율 {mal.mean():.3f} ({int(mal.sum())}/{mal.count()})  정상 오탐률 {ben.mean():.3f} ({int(ben.sum())}/{ben.count()})")
for g in ["provenance", "source_id"]:
    if g in m:
        print(f"\n{g}별 걸린 비율 (label 1=재현율, 0=오탐률):")
        print(m.groupby([g, "label"])[tools].agg(["mean", "count"]).round(3).to_string())
both = m[(m.label == 1) & (m.cisco_any == 0) & (m.skillgate == 0)]
print("\n두 도구 모두 놓친 악성:", len(both), "/", int((m.label == 1).sum()))
m.to_csv(f"{run}/scores.csv", index=False)
