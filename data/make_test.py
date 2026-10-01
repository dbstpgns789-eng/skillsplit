import pandas as pd, os
df = pd.read_csv("skills.csv")
sp = pd.read_csv("source_disjoint.csv")
m = df.merge(sp[["benchmark_id", "split"]], on="benchmark_id")
t = m[m["split"] == "test"]
for _, r in t.iterrows():
    d = os.path.join("test_skills", r["benchmark_id"])
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "SKILL.md"), "w", encoding="utf-8") as f:
        f.write(str(r["skill_text"]) if pd.notna(r["skill_text"]) else "")
t[["benchmark_id", "label", "provenance"]].to_csv("test_labels.csv", index=False)
print("폴더 수:", len(os.listdir("test_skills")))