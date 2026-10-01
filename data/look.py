import pandas as pd
df = pd.read_csv("skills.csv")
print("라벨:", df["label"].value_counts().to_dict())
print("출처:", df["provenance"].value_counts().to_dict())
print("악성만 출처:", df[df["label"] == 1]["provenance"].value_counts().to_dict())
print("텍스트 길이 중앙값:", int(df["skill_text"].str.len().median()), "최대:", int(df["skill_text"].str.len().max()))