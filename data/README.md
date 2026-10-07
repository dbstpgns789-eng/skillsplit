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
- 백신이 파일을 지울 수 있다. 폴더 수가 100보다 적으면 Windows Defender 격리함을 확인한다. 폴더는 남고 `SKILL.md`만 사라지기도 하므로, 폴더 수가 아니라 **파일 수와 해시**로 확인한다.
- Windows에서 스킬 파일을 쓸 때는 `open(..., newline="")`로 쓴다. 그냥 쓰면 줄바꿈이 `\r\n`으로 바뀌어 원문과 달라진다(`make_dev.py` 참고).

## 다른 파일

| 파일 | 뭐 하는 것 |
|---|---|
| `look.py` | 받은 데이터 세어 보기 (라벨, 출처, 길이) |
| `split.py` | 공식 분할 붙여서 test 구성 보기 |
| `peek.py` | 실제 악성 스킬 몇 개 열어 보기 |
| `get_rules.py` | SkillGate·Cisco 공개 규칙을 고정 버전으로 받아 `rules_all.csv`(정규식 한 줄씩)로 합치기. `pip install pyyaml` 필요 |
| `make_dev.py`, `run_skillgate.py`, `score.py` | 공부용 전체(8,348개)를 `dev_skills/`로 풀고, SkillGate(규칙만)·Cisco(정적)를 돌려 채점. 사용법은 각 파일 맨 위 주석 |
| `sg_attack_only.py` | SkillGate가 60초 안에 못 끝낸 샘플을 sigma 뺀 attack 규칙만으로 판정 확인. `.venv-skillgate/Scripts/python sg_attack_only.py <SKILL.md>` |
| `signals.py` | 두 도구가 놓친 악성에서 찾은 행위 신호 6개를 dev 전체에서 집계(원문 출력 없음). `python signals.py` → `runs_dev/signals.csv` |
| `make_test.py`, `count_cisco.py` | 대표가 Cisco 기준선 돌릴 때 쓰는 것. 팀원은 안 써도 됨 |
