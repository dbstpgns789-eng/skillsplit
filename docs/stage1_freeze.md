# 정적 탐지기 동결 자료 (왕민)

작성 2026-11-05. 공통 동결(이번 주말 저녁) 전에 정적 파트의 상태·실행 조건·결과·해석·예상을 한곳에 모은다. 상세 분석은 [E5](experiments/E5_stage1_v0.md)(v0), [E6](experiments/E6_stage1_v1.md)(v1), 설계는 [stage1 README](../skillsplit/stage1/README.md).

에이전트(Claude)와 함께 작성했다. 표의 숫자는 아래 명령의 출력에서 옮겼다. "추정"이라고 쓴 곳은 확인하지 않은 원인 설명이다.

## 1. 현재 상태

| 항목 | 상태 | 비고 |
|---|---|---|
| 규칙 17개 구현·테스트(pytest 40개) | 완료 | 탐지기 코드 `31333de` 이후 `rules.py`·`scan.py` 변경 없음 |
| dev 전체·dev100 실행, 공통 형식 결과 | 완료 | `results/stage1/` |
| PR #4 리뷰 1~4번(가중치, 비교 조건, PR-AUC 해석, RUN 분리) | 완료 | E6 §2·§3, E5 §0 |
| 작은 출처 미탐 사례 판정 | 1차 완료 | 40개, 에이전트 1차 판정. **담당자 원문 대조 남음**(동결 전) |
| script-only 기준 | 초안 | E6 §8. 세훈 님과 확정(동결 전) |
| test 집계 스크립트 | 완료 | `data/s1_eval.py` |
| AST(tree-sitter-bash, Python `ast`) | 보류(넣지 않음) | dev 상한 6개(E6 §6). 후속 범위는 test 뒤 세훈 님과 정함 |
| 동봉 스크립트 분석 탐지기 | 범위 밖 | 공지 5번대로 후속 작업 |

## 2. 실행 조건

| 항목 | 값 |
|---|---|
| 탐지기 코드 | `skillsplit/stage1/rules.py`, `scan.py` (커밋 `31333de`). 이 문서가 들어간 커밋에서도 같음 |
| 환경 | Windows 11, Python 3.12.10. 탐지기는 표준 라이브러리만 씀. 집계는 `pandas`, 테스트는 `pytest` |
| 설치 | `python -m pip install pandas pytest` |
| 입력 | 스킬 폴더 아래 `<benchmark_id>/SKILL.md`. SKILL.md만 읽고 동봉 파일은 읽지 않음. `stage2/common.read_skill`(UTF-8, 오류 문자는 대체)로 읽어 2단계와 같은 입력 |
| 데이터 분할 | 공식 `source_disjoint.csv`. dev = train+validation 8,348 (악성 6,658 / 정상 1,690) |
| 입력 확인 | `s1_eval.py`가 SKILL.md 파일 수, 정답과의 id 차이, `skills.csv` `skill_text`와의 sha256을 확인. dev 8,348개 모두 일치. 로컬 dev100 사본 100개는 줄바꿈만 CRLF(`read_text`가 LF로 읽어 탐지기 입력은 같음) |
| 규칙 버전 | v1, 17개. 목록은 E6 §7 |
| 입력 제한 | 200,000자 넘으면 details에 `oversize=true`, 앞 300,000자만 검사(`scanned_chars` 기록). dev에서 oversize 1개, 잘림 1개, 빈 SKILL.md 5개 |
| 걸림 기준(문턱) | **score > 0** 유지. 발동한 규칙이 하나라도 있으면 걸림. 결합 전용 규칙(CONCEAL, DESC_BYPASS)은 짝이 있어야 발동. 가중치가 쌓여야 걸리는 구조가 아님 |
| 점수 | 걸린 규칙의 가중치 noisy-OR(CRITICAL 0.9, HIGH 0.7, MEDIUM 0.4, LOW 0.2). PR-AUC용. 가중치가 모두 양수라 값을 바꿔도 걸림 여부는 바뀌지 않음 |
| 실패 처리 | 정적은 실패가 없다(모든 스킬에 점수). 정규식 컴파일 실패는 import 때 오류. 20MB 한 줄을 5초 안에 처리하는 테스트 있음 |
| 실행 날짜·횟수 | dev 전체·dev100 각 1회(2026-11-04). 결정적이라 반복해도 같음 |

### 2.1 test 실행 순서 (세훈 님)

```
git checkout <동결 커밋>
python -m pip install pandas pytest
python -m pytest tests/test_stage1.py                                   # 40 passed
python -m skillsplit.stage1.scan <test 스킬 폴더> --out runs/stage1_v1_test.jsonl
cd data
python s1_eval.py <test 스킬 폴더> ../runs/stage1_v1_test.jsonl <test 정답 csv: benchmark_id,label[,source_id]>
#   script-only 기준 확정 후: --script-only <판정 csv: benchmark_id,verdict>
```

- `s1_eval.py` 출력: 파일 수·해시·누락·중복·생략 건수, 전체와 출처별 "악성 걸림/악성", "정상 걸림/정상".
- 결과 파일: `runs/stage1_v1_test.jsonl`(공통 형식 `{"skill_id", "score", "evidence"}`), `runs/stage1_v1_test.details.jsonl`(oversize, scanned_chars, empty).

### 2.2 기준선 비교 조건 (E1)

| 도구 | 버전·옵션 | 걸림 | 실패 처리 |
|---|---|---|---|
| Cisco | `cisco-ai-skill-scanner==2.2.1`, `skill-scanner scan-all <dir> --format json`, 정적만(LLM 끔). 기본 설정 결과와 `--use-behavioral`(논문 설정) 결과 둘 다 | `is_safe == False` | 60초 넘으면 스캔 실패로 빼고 건수 보고. dev 실패 0 |
| SkillGate | `awsm-research/skillgate@c1641c5`, `create_classifier(use_llm=False)`(규칙만). 동작 규칙 530개(533개 중 3개 컴파일 실패) | 규칙 하나라도 걸리면 악성 | 60초 넘으면 실패. dev 1개(`ASB04_002434`)는 attack 규칙만으로 CRED014 확인해 악성으로 채움 |

## 3. 결과 (dev)

| 조건 | 재현율 | 오탐률 |
|---|---:|---:|
| v1 전체 | 3,653/6,658 = 0.549 | 13/1,690 = 0.008 |
| v1, 출처 편향 규칙 9개 제외 | 1,065/6,658 = 0.160 | 9/1,690 = 0.005 |
| v1, 반복 틀 RUN 줄로만 잡힌 1,482개 제외 | 2,171/6,658 = 0.326 | 13/1,690 |
| v0 | 3,653/6,658 = 0.549 | 21/1,690 = 0.012 |
| Cisco 2.2.1 정적 (E1) | 2,063/6,658 = 0.310 | 14/1,690 = 0.008 |
| SkillGate 규칙만 (E1) | 2,810/6,658 = 0.422 | 428/1,690 = 0.253 |
| dev100, v1 | 32/50 = 0.640 | 0/50 |

출처별(v1, 악성 걸림/악성): SRC001 1,396/3,418, SRC002 87/153, SRC004 4/33, SRC005 3/30, SRC006 10/86, SRC008 1/1, SRC010 2,147/2,783, SRC013 5/154. 정상 걸림/정상: SRC010 13/1,643, SRC006 0/45, SRC008 0/2.

누락 0, 중복 0, 실패 0, 입력 생략(앞 300,000자만 검사) 1개(dev 전체), dev100 0.

script-only 제외 재현율은 기준 확정 전이라 내지 않는다(E6 §8. 지금까지 분류한 90개만으로는 3,653/6,645 = 0.550).

결과 파일(원문 없음):
- `results/stage1/stage1_v1_dev.jsonl`, `stage1_v1_dev100.jsonl`과 각 `.details.jsonl`: 공통 형식
- `results/stage1/script_evidence_dev.csv`: dev 악성 6,658개의 동봉 코드 근거(`파일:줄:동작`), script-only 검토용

## 4. 해석

### 4.1 v0 → v1 변경과 효과 (dev)

| 변경 | 효과 (관찰) |
|---|---|
| RUN_DIRECTIVE → RUN_CMD·RUN_INIT (정규식 그대로) | 걸림 여부 변화 없음. 출처·반복 틀을 따로 셀 수 있게 됨 |
| CRED_PATH: `ssh-add`·`ssh-keygen`·`ssh -i`로 시작하는 줄 예외 | 오탐 21 → 13, 재현율 변화 없음(3,653/6,658) |
| 채택 기준 2에 최다 출처 비중 < 90% | 점수 변화 없음(편향 규칙도 점수에 남김). 보고에 "편향 제외 재현율" 추가 |

### 4.2 시도했지만 넣지 않은 것

| 시도 | 이유 |
|---|---|
| AST(줄을 넘는 디코드+실행, pipe-to-shell) | dev에서 더 잡을 수 있는 상한 6개 |
| SkillGate CMD033·RCE009·DISC101 옮기기 | 새로 잡는 악성이 정상 오탐과 같은 형태(`cat ~/.설정`, `$(cat /tmp/…)`), DISC101은 펜스 줄 오인 |
| PERSISTENCE에 `echo 'export …' >>` 예외 | 정상 −5지만 악성 −3 |
| HOMOGLYPH에서 그리스 문자 빼기 | 악성 적중 63개 중 31개가 그리스 문자만 섞인 경우 |
| script-only = "동봉 코드 있음" | 공지와 맞지 않고 글 공격도 빠짐. 철회(E6 §8.1) |
| script-only = 코드 키워드 조합 | E4 script_only를 6/10만 걸러냄 |

### 4.3 대표 오탐·미탐 근거

- 오탐: 남은 13개는 모두 SRC010 정상이다.
  - PERSISTENCE 6: 설치 안내의 `echo 'export KEY=…' >> ~/.zshrc` 5개, `systemctl --user enable` 1개
  - PROMPT_LEAK 2: 문맥 창을 설명하는 문장에 "system prompt"
  - HOMOGLYPH 2: `μm`, `ΔC` 같은 단위
  - LURE·HIDDEN_DIRECTIVE·PIPE_TO_SHELL 각 1
- 미탐(작은 출처 40개 판정, E6 §5.2):
  - 규칙 범위 부족 8: 가짜 선행 설치 유도, 산문으로 쓴 유출 설명, 출력에 파일 내용 넣기, OpenClaw 예약 등록 등
  - 문서에 없는 증거 3: 동봉 스크립트의 자격증명 경로 읽기, 내려받아 실행
  - 판단 불확실 29

### 4.4 남은 한계와 다음 가설

- 관찰: 재현율의 상당 부분이 dev의 큰 두 출처(SRC001·SRC010)의 문장 틀에서 나온다. 출처 편향 제외 0.160, 반복 틀 제외 0.326이다.
- 관찰: dev 정상의 97%가 SRC010이라 오탐률 0.008은 한 출처 정상에서 잰 값이다.
- 추정: 작은 출처의 미탐은 정해 둔 단어 목록에 없는 표현과 실행해 봐야 드러나는 동작(출력 조작) 때문이다. 정적 규칙으로 메우기 어렵다.
- 다음 가설(test 뒤, 탐색적 개선으로 표시):
  - 가짜 선행 설치 유도·출력에 파일 내용 넣기를 행위 규칙으로 일반화하면 작은 출처 재현율이 오를 수 있다.
  - 동봉 스크립트 분석은 script-only 3/40 몫을 줄일 수 있다.

## 5. 기존 연구와 다른 점 (우리 설계)

| 설계 | 기존 도구 | dev에서 확인된 효과 | 확인 안 된 것 |
|---|---|---|---|
| 글 규칙: 기존 도구가 놓친 악성(E2~E4)에서 뽑은 에이전트 지시형 규칙(실행 유도, 지시 무력화, 프롬프트 유출 등) | Cisco·SkillGate는 명령·키워드·코드 위주(E1) | Cisco·SkillGate가 둘 다 놓친 악성 중 새로 잡은 수(new_vs_baselines): RUN_CMD 890, RUN_INIT 281, OVERRIDE 92 등(E6 §1). **dev는 설계 데이터라 유리** | 다른 출처로의 일반화(test에서 확인) |
| 영역 나누기: frontmatter / 산문 / 코드 블록마다 다른 규칙 | — | 산문 규칙이 코드 예시에, 코드 규칙이 설명 문장에 걸리지 않음(테스트로 확인) | 영역 나누기 자체의 성능 기여는 따로 재지 않음 |
| 단일 명령 규칙 배제, 결합 전용 규칙(CONCEAL·DESC_BYPASS는 짝이 있을 때만) | SkillGate는 `curl` 같은 단일 명령도 규칙(CMD001, dev 정상 6.9%) | 오탐률 0.008 vs SkillGate 0.253 | 결합 전용 규칙의 기여는 따로 재지 않음 |
| 출처 편향 기준(출처 수 + 최다 출처 비중)과 편향 제외 재현율 보고 | — | 편향 제외 재현율 0.160을 함께 보고 | — |
| 반복 틀 측정(출처와 무관) | — | RUN_CMD의 78%가 반복 틀(8단어 기준) | — |
| 안전장치: 정규식 컴파일 실패 시 즉시 오류, 반복 상한, 20MB 한 줄 테스트 | SkillGate는 3개를 조용히 빼고, 20MiB 한 줄에서 멈춤(E1 §3) | dev 8,348개 실패 0 | — |
| 결과 형식: `규칙@줄번호` evidence, 2단계와 같은 형식 | — | 네 칸 분해·사례 확인에 씀 | — |

## 6. test 예상 (실행 전 기록)

**재현율 0.05~0.20, 오탐률 0.5~3%.**
- 재현율 근거: test는 dev에 없는 출처로만 구성된다. dev에서 한 출처에 맞춘 규칙을 뺀 재현율이 0.160이고, dev 작은 출처의 재현율은 0.03~0.12(SRC002 0.57 제외)다.
- 오탐률 근거: dev 오탐 13개는 설치 안내·단위 기호처럼 어느 출처의 정상에도 있을 형태다. dev 정상은 한 출처뿐이라 범위를 넓게 잡았다.

이 예상은 담당자가 확인하고 고칠 수 있다(동결 전).
