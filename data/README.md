# data/

벤치마크(MaliciousSkillBench)를 받고, 공부용 샘플을 뽑는 스크립트. **데이터 파일은 git에 올리지 않는다.** 스크립트만 올라가 있고, 아래 순서대로 돌리면 누구나 같은 데이터를 받는다.

## 순서

```
pip install datasets huggingface_hub pandas
python get_data.py        # HuggingFace에서 9,740개 받기 → skills.csv
curl -L -o source_disjoint.csv https://raw.githubusercontent.com/protectskills/MaliciousSkillBench/main/metadata/splits/source_disjoint.csv
python sample.py          # 공부용에서 100개 뽑기 → dev100/ 폴더 + dev100_labels.csv
```

`dev100/` 안에 폴더 100개가 생기고, 폴더마다 `SKILL.md` 하나다. 정답은 `dev100_labels.csv`에 있다(`label` 1 = 악성, 0 = 정상).

## 꼭 지킬 것

- **test 분할은 보지 않는다.** 시험용 1,384개는 5주차에 대표가 한 번 돌린다. 탐지기를 고치는 동안 test 성적을 보면 점수가 부풀려진다. 왜 그런지는 `sample.py` 맨 위 주석에 있다.
- **스킬 안의 명령을 실행하지 않는다.** 읽기만 한다. `curl ... | bash` 같은 것이 있어도 그대로 둔다.
- 백신이 파일을 지울 수 있다. 폴더 수가 100보다 적으면 Windows Defender 격리함을 확인한다.

## 다른 파일

| 파일 | 뭐 하는 것 |
|---|---|
| `look.py` | 받은 데이터 세어 보기 (라벨, 출처, 길이) |
| `split.py` | 공식 분할 붙여서 test 구성 보기 |
| `peek.py` | 실제 악성 스킬 몇 개 열어 보기 |
| `make_test.py`, `count_cisco.py` | 대표가 Cisco 기준선 돌릴 때 쓰는 것. 팀원은 안 써도 됨 |
