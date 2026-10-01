import pandas as pd
df = pd.read_csv("skills.csv")
w = df[(df["label"] == 1) & (df["provenance"] == "wild")]
print("실제 악성 수:", len(w))
print("공격 종류:", w["attack_category_codes"].value_counts().head(8).to_dict())
for i, row in w.sample(3, random_state=1).iterrows():
    print("\n" + "=" * 60)
    print(row["benchmark_id"], "|", row["attack_category_codes"])
    print(str(row["skill_text"])[:1500])