"""프롬프트를 고친 뒤 과적합 확인용 두 번째 표본: dev에서 dev100을 뺀 나머지 중 악성·정상 50개씩.

dev100의 틀린 사례를 읽고 프롬프트를 고치면 그 100개에만 맞춰질 수 있다.
그래서 고친 프롬프트는 한 번도 읽지 않은 다른 dev 스킬로 다시 잰다. test는 쓰지 않는다.

  cd data && python ../skillsplit/stage2/sample_check.py   → devcheck100/<id>/SKILL.md + devcheck100_labels.csv
"""
import os

import pandas as pd

df = pd.read_csv("skills.csv")
sp = pd.read_csv("source_disjoint.csv")
m = df.merge(sp[["benchmark_id", "split"]], on="benchmark_id")
dev = m[m["split"].isin(["train", "validation"])]
pool = dev[~dev["benchmark_id"].isin(os.listdir("dev100"))]
s = pd.concat([pool[pool["label"] == 1].sample(50, random_state=7),
               pool[pool["label"] == 0].sample(50, random_state=7)])

for _, r in s.iterrows():
    d = os.path.join("devcheck100", r["benchmark_id"])
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "SKILL.md"), "w", encoding="utf-8", newline="") as f:  # 줄바꿈을 원문 그대로
        f.write(str(r["skill_text"]) if pd.notna(r["skill_text"]) else "")

s[["benchmark_id", "label", "provenance", "source_id"]].to_csv("devcheck100_labels.csv", index=False)
print("devcheck100:", len(s), "개", s.groupby("label")["source_id"].value_counts().to_dict())
