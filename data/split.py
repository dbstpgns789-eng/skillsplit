import pandas as pd
df = pd.read_csv("skills.csv")
sp = pd.read_csv("source_disjoint.csv")
print("분할 파일 열:", list(sp.columns))
m = df.merge(sp[["benchmark_id", "split"]], on="benchmark_id")
print("분할별 수:", m["split"].value_counts().to_dict())
t = m[m["split"] == "test"]
print("test 라벨:", t["label"].value_counts().to_dict())
print("test 악성의 출처:", t[t["label"] == 1]["provenance"].value_counts().to_dict())
print("test 정상의 출처:", t[t["label"] == 0]["provenance"].value_counts().to_dict())