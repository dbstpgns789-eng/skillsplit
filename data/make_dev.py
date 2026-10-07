import pandas as pd, os
df = pd.read_csv("skills.csv")
sp = pd.read_csv("source_disjoint.csv")
m = df.merge(sp[["benchmark_id", "split"]], on="benchmark_id")
t = m[m["split"].isin(["train", "validation"])]  # 공부용 전체. test는 제외
for _, r in t.iterrows():
    d = os.path.join("dev_skills", r["benchmark_id"])
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "SKILL.md"), "w", encoding="utf-8", newline="") as f:  # Windows에서도 원문 줄바꿈(LF) 유지
        f.write(str(r["skill_text"]) if pd.notna(r["skill_text"]) else "")
t[["benchmark_id", "label", "split", "provenance", "source_id", "attack_category_codes"]].to_csv("dev_labels.csv", index=False)
print("폴더 수:", len(os.listdir("dev_skills")))
