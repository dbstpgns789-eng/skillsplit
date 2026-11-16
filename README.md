# skillsplit

**Textrap** 팀 · 2026 하반기 SW·AI융합연구개발 일반과제 (한양대 ERICA SW중심대학사업단, 팀 15)
2026 한양대학교 SW·AI 종합학술대회 C-2 "정적 분석과 LLM 지시문 판정을 결합한 AI 에이전트 악성 스킬 2단계 탐지"

AI 에이전트 스킬의 악성 여부를 정적 규칙, LLM 판정기, Jev(스킬 검사 전용 모델)로 검사하고, 공개 벤치마크에서 각 탐지기가 **무엇을 놓치고 왜 놓치는지** 잰다.

## 결과 요약

평가 데이터: MaliciousSkillBench 출처 분리(Source-Disjoint) 분할의 test 1,384개(악성 839, 정상 545). 개발에 쓰지 않은 출처로만 구성된다. 판정 기준은 개발 데이터로 정해 `freeze-v1` 태그로 고정한 뒤 한 번 실행했다.

| 탐지기 | 기준 | 재현율 (악성 839) | 오탐률 (정상 545) |
|---|---|---|---|
| 정적 규칙 v1 | 점수 > 0 | 8.5% (71) | 4.6% (25) |
| LLM (Claude Haiku 4.5, 프롬프트 v2) | 점수 ≥ 2/3 | 29.9% (251) | 0.7% (4) |
| Jev | 점수 ≥ 0.5 | 14.9% (125) | 0.0% (0) |
| 참고: Cisco skill-scanner (MaliciousSkillBench 논문 설정) | | 1.6% (13/834) | 1.1% (6/534) |

발견:

1. **정상 스킬을 개조한 공격은 세 탐지기 모두 대부분 놓쳤다.** LLM 재현율은 처음부터 악성으로 만든 스킬(synthetic, 90개)에서 81.1%, 정상 스킬에 공격을 끼워 넣은 스킬(injected, 570개)에서 24.4%, 숨은 장치를 심은 스킬(backdoored, 158개)에서 12.0%였다. 세 탐지기가 모두 놓친 악성 545개 중 540개가 injected·backdoored였다. 이 test에서는 출처와 공격 유형이 완전히 겹치므로 둘 중 무엇이 원인인지는 나누지 못했다.
2. **탐지기가 읽지 않는 파일에도 공격이 있었다.** 동봉 파일이 있는 악성 100개를 두 사람이 열어 판정한 결과(교차 일치 18/20), 공격은 SKILL.md 본문 32, 스크립트에만 34, 동봉 문서(PDF·md)에만 23, 판단 불가 11이었다. 세 탐지기는 SKILL.md 본문만 읽는다.
3. **그래도 코드에 숨은 공격이 낮은 성적의 주된 원인은 아니다.** 스크립트에만 있는 공격을 빼고 추정해도 재현율은 0.7~3.5%p 올랐다(정적 9.2%, LLM 33.0%, Jev 18.4%, 유한모집단 베이즈 추정 중앙값).
4. **본문에 있어도 업무 지시로 위장하면 놓쳤다.** 본문 공격 32개 중 명령을 그대로 쓴 공격은 10/21, 말로 풀어 쓴 공격은 2/11을 하나 이상의 탐지기가 잡았다. 업무 결과를 조작하는 공격(보고서 문구 강제, 느슨한 송장 대조 등)은 0/5였다.

공격 유형별 수치(1번)는 test 결과 파일과 벤치마크의 provenance 필드로 다시 계산한 값이다. 본문 공격 분류(4번)는 최종보고서에 정리하며, 표본이 작은 하위 분류(5~11개)는 경향으로만 읽어야 한다. 전체 성적의 조건은 아래 문서에 있다.

## 문서

| 문서 | 내용 |
|---|---|
| [`docs/study-guide.md`](docs/study-guide.md) | 과제가 무엇이고 왜 하는지, 처음부터 끝까지 |
| [`docs/stage2-test.md`](docs/stage2-test.md) | test 실행 조건, 결과 파일 해시, 출처별·결합·비용 결과 |
| [`docs/experiments/stage2_test_report.md`](docs/experiments/stage2_test_report.md) | 문턱별 전체 표 (`report_thresholds` 출력) |
| [`docs/stage1_freeze.md`](docs/stage1_freeze.md), [`docs/stage2-freeze.md`](docs/stage2-freeze.md) | 동결 시점의 탐지기 설정, 실행 명령, 실행 전 예상 |
| [`docs/script_only_proposal.md`](docs/script_only_proposal.md), [`docs/experiments/script_only_test_sheet.csv`](docs/experiments/script_only_test_sheet.csv) | 공격 위치 판정 기준과 test 표본 100개 판정 |
| [`docs/experiments/`](docs/experiments/) | 개발 중 실험 기록(E1~E6) |
| [`docs/research/`](docs/research/) | 자료조사 보고서 네 편(정적 규칙, LLM 판정기, 기성 스캐너, 평가 규약). 모든 수치에 원문 URL |
| [`docs/decisions.md`](docs/decisions.md) | 설계 결정과 바뀐 이유 |

## 구성

| 경로 | 내용 |
|---|---|
| `skillsplit/stage1/` | 정적 규칙 탐지기 |
| `skillsplit/stage2/` | LLM·Jev 판정기, 데이터 확인, 문턱별 집계 |
| `data/` | 벤치마크 받기, 분할 만들기, 기준선 실행, 공격 위치 표본·추정 스크립트 ([`data/README.md`](data/README.md)) |
| `results/stage1/` | 정적 탐지기 개발 데이터 결과 |
| `tests/` | 단위 테스트 |

## 재현

데이터 파일은 저장소에 올리지 않는다. 받는 방법은 [`data/README.md`](data/README.md), 탐지기별 실행 명령은 [`docs/stage1_freeze.md`](docs/stage1_freeze.md)와 [`docs/stage2-freeze.md`](docs/stage2-freeze.md)에 있다. 성적은 `freeze-v1` 태그(`b0ff1e0`)의 코드로 냈다.

```
git checkout freeze-v1
python -m pip install pandas pytest
python -m skillsplit.stage1.scan <스킬 폴더> --out runs/stage1_v1_test.jsonl
python -m skillsplit.stage2.llm_judge <스킬 폴더> --out runs/stage2_llm_v2_test_r1.jsonl
python -m skillsplit.stage2.jev_judge <스킬 폴더> --out runs/stage2_jev_v0_test_r1.jsonl --via vercel
```

LLM·Jev 실행에는 API 키가 필요하다. 벤치마크의 악성 스킬에는 실제로 동작하는 명령이 들어 있으므로 **스킬 안의 명령을 실행하지 말고**, 백신이 파일을 격리할 수 있으니 파일 수와 해시로 확인한다.

## 팀

윤세훈(대표), 오준서, 왕민 — 한양대 ERICA 인공지능학과. 지도교수 박지현

## 라이선스

MIT
