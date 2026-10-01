import json, pandas as pd
res = json.load(open("cisco_result.json", encoding="utf-8"))
items = res if isinstance(res, list) else res.get("results", res.get("skills", []))
rows = []
for it in items:
    path = str(it.get("skill_path", it.get("path", "")))
    bid = path.replace("\\", "/").rstrip("/").split("/")[-1].upper()
    rows.append({"benchmark_id": bid, "flag": 0 if it.get("is_safe", True) else 1,
                 "sev": it.get("max_severity", "")})
pred = pd.DataFrame(rows)
lab = pd.read_csv("test_labels.csv")
m = lab.merge(pred, on="benchmark_id", how="left")
print("스캔 성공:", m["flag"].notna().sum(), "/ 실패:", m["flag"].isna().sum())
ok = m[m["flag"].notna()]
mal = ok[ok["label"] == 1]; ben = ok[ok["label"] == 0]
print("악성 재현율:", round(mal["flag"].mean(), 3), f"({int(mal['flag'].sum())}/{len(mal)})")
print("정상 오탐률:", round(ben["flag"].mean(), 3), f"({int(ben['flag'].sum())}/{len(ben)})")
print("심각도 분포:", ok["sev"].value_counts().to_dict())