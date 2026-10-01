# sample.py
# 팀원에게 주는 첫 개발용 샘플 100개를 뽑는다.
#
# 왜 100개만 주나
#   처음 만든 탐지기를 9,740개에 돌리면 오래 걸리고, 틀린 것을 하나하나 열어 볼 수 없다.
#   100개면 몇 초에 돌고 틀린 것을 손으로 확인할 수 있다. 시동용이다.
#   돌아간다 싶으면 공부용 전체(8,348개)로 넓힌다.
#
# 왜 공부용(train+validation)에서만 뽑나
#   벤치마크는 공부용과 시험용(test 1,384개)이 나뉘어 있다. 시험용은 5주차에 딱 한 번 본다.
#   탐지기를 고치는 동안 시험용 성적을 보면 "시험 문제 보면서 공부하기"가 되어 점수가 부풀려진다.
#   그래서 팀원은 시험용을 받지 않는다. 대표가 갖고 있다가 마지막에 돌린다.
#
# 왜 고정된 시드(random_state=42)인가
#   세 사람이 같은 100개를 가져야 "나는 되는데 너는 안 된다"가 생기지 않는다.
#
# 쓰는 법
#   python get_data.py  → skills.csv          (벤치마크 9,740개)
#   curl ... source_disjoint.csv              (공식 분할 파일. split.py 위 주석 참고)
#   python sample.py    → dev100/<id>/SKILL.md 100개 + dev100_labels.csv (정답)

import pandas as pd, os

df = pd.read_csv("skills.csv")
sp = pd.read_csv("source_disjoint.csv")
m = df.merge(sp[["benchmark_id", "split"]], on="benchmark_id")

dev = m[m["split"].isin(["train", "validation"])]          # 공부용만. test는 제외
mal = dev[dev["label"] == 1].sample(50, random_state=42)   # 악성 50
ben = dev[dev["label"] == 0].sample(50, random_state=42)   # 정상 50
s = pd.concat([mal, ben])

for _, r in s.iterrows():
    d = os.path.join("dev100", r["benchmark_id"])
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "SKILL.md"), "w", encoding="utf-8") as f:
        f.write(str(r["skill_text"]) if pd.notna(r["skill_text"]) else "")

s[["benchmark_id", "label", "provenance", "attack_category_codes"]].to_csv("dev100_labels.csv", index=False)
print("dev100 폴더:", len(os.listdir("dev100")), "개")
print("정답 파일: dev100_labels.csv  (label 1=악성, 0=정상)")
print("출처:", s["provenance"].value_counts().to_dict())