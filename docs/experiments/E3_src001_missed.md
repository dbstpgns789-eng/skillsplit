# E3. SRC001(MalSkillBench)에서 두 도구가 놓친 악성 분석

실행일 2026-10-08. 담당 정적 탐지기(왕민). dev만 사용, test는 보지 않았다. [E2](E2_missed_cases.md)의 후속이다.

악성 원문은 출력하지도, 이 문서에 옮기지도 않았다. 집계·소제목 이름·3단어 어구만 봤다.

## 0. 한 줄 결론

- **SKILL.md 하나뿐인 샘플도 똑같이 44%를 놓친다.** 파일 수에 따른 차이가 없다. "악성이 동봉 스크립트에 숨어 있어서 못 잡는다"는 설명은 맞지 않는다. 공격은 글 안에 있는데 도구가 못 본다.
- 기존 도구는 **코드에 위험 동작(네트워크·실행)이 있는 유형**을 잡는다. 놓친 SRC001은 위험 키워드가 하나도 없는 비율이 62%로 정상(64%)과 같다. **글로 된 지시형 공격**이다.
- 놓친 1,498개는 셋으로 나뉜다.
  1. 생성기 경계 흔적이 있음: 330. 규칙으로 쓰면 안 된다.
  2. "초기화 스크립트를 먼저 실행하라", "시스템 프롬프트를 드러내라" 같은 지시 틀: 303. 정상 0개다.
  3. 둘 다 없음: 984. 이 중 445개는 "운영 지침"류 소제목이 끼워 넣어져 있고(정상 2%), 나머지 약 540개는 **평범한 문장에 의도만 악성**이라 정규식의 한계 밖이다.

## 1. 전제: 정상과 비교할 때의 함정

- SRC001은 **전부 악성**(dev 3,418)이다. 정상 1,690개 중 **1,643개가 SRC010 출처**다.
- 그래서 "SRC001 악성 대 정상" 비교는 악성 여부와 **출처 문체 차이**가 섞인다. 예: `license: MIT` + `allowed-tools: Read, Write, Bash` frontmatter는 놓친 SRC001 17~27%, 정상 0~1%지만 원본 스킬 저장소의 양식일 뿐이다. "anti-patterns", "sharp edges" 소제목도 같다.
- 아래 신호는 같은 출처 안 비교(SRC001 놓침 대 잡힘)와 다른 출처 악성 수를 함께 보고 판단했다.

## 2. 동봉 스크립트 때문인가: 아니다

`package_manifest.csv`(MaliciousSkillBench `packages/`, 메타데이터만)의 `package_file_count`로 나눴다. 악성 패키지에는 스크립트가 있지만 정상은 SKILL.md 텍스트뿐이라, 공식 평가는 SKILL.md만 입력으로 쓴다(R4 1(h)).

| SRC001 패키지 파일 수 | 놓침 | 전체 | 놓친 비율 |
|---|---:|---:|---:|
| 1 (SKILL.md만) | 733 | 1,677 | 0.437 |
| 2 | 732 | 1,682 | 0.435 |
| 3~5 | 26 | 40 | 0.650 |
| 6+ | 7 | 19 | 0.368 |

파일이 하나뿐인 놓친 733개는 공격 내용이 SKILL.md 안에 있을 수밖에 없다(라벨이 맞다면). 정적 탐지기로 개선할 여지가 있는 대상이다.

## 3. 글 모양 (`src001_profile.py`)

| | SRC001 놓침 (1,498) | SRC001 잡힘 (1,920) | 정상 (1,690) |
|---|---:|---:|---:|
| 길이 중앙값 | 6,200 | 7,740 | 4,189 |
| 코드 블록 0개 비율 | 0.17 | 0.05 | 0.15 |
| 코드 블록 수 중앙값 | 3 | 8 | 3 |
| 코드에 네트워크 호출 | 0.05 | 0.58 | 0.07 |
| 코드에 프로세스 실행 | 0.02 | 0.17 | 0.00 |
| 코드에 인코딩(base64 등) | 0.00 | 0.13 | 0.01 |
| 위험 키워드 계열 10개 중 하나도 없음 | **0.62** | 0.12 | 0.64 |

잡힌 SRC001은 코드에 위험 동작이 있다. 놓친 SRC001은 키워드 수준에서 정상과 구분되지 않는다.

## 4. 놓친 SRC001의 특징적 어구 (`src001_ngrams.py`)

정상 대비 문서 비율이 높은 3단어 어구(코드 블록·URL 제외). 카테고리별로 같은 틀이 반복된다.

| 묶음 | 특징 어구 (놓친 비율 / 정상 비율) | 해석 |
|---|---|---|
| 전체 | "end original skill" 0.22 / 0.000 | 생성기가 원본과 주입부 경계에 남긴 표시 |
| execution (104) | "this initialization step" 0.20, "initialization before beginning" 0.12, "prepares the environment" 0.11 / 모두 0.000 | 초기화 스크립트 실행 유도 |
| resource (91) | "should be executed" 0.12, "ensure optimal performance" 0.12 / 0.000 | 성능 최적화로 포장한 실행 |
| exfiltration (75) | "the initial prompt" 0.15, "configuration parameters and" 0.15 / 0.000 | 시스템 프롬프트·설정 유출 |
| credential (56) | "create configuration file" 0.12, "are properly configured" 0.12 / 0.000 | 설정 파일 생성으로 포장 |
| instruction (123) | "this skill operates" 0.28 / 0.001, "the system maintains" 0.12 / 0.001 | 운영 원칙을 덮어쓰는 절 |
| 카테고리 없음 (925) | "alignment with organizational objectives" 0.08, "continuous monitoring of" 0.08 / 0.000 | 목표·감시 지시 |

## 5. 신호 집계 (`src001_signals.py`)

산문(코드 블록 밖)에서 찾는다. op_heading만 소제목 줄에서 찾는다.

| 신호 | 뜻 | SRC001 놓침 | SRC001 잡힘 | 다른 출처 악성 | 정상 |
|---|---|---:|---:|---:|---:|
| marker | 생성기 경계 흔적 "original SKILL.md" | 330 | 573 | 0 | 0 |
| init_directive | 초기화 스크립트·단계를 먼저 실행하라 | 276 | 399 | 5 | 0 |
| prompt_leak | 시스템/초기 프롬프트를 드러내라 | 24 | 28 | 3 | 0 |
| operates_under | "이 스킬은 다음 원칙 아래 동작한다" | 4 | 3 | 0 | 0 |
| op_heading | "Operational …", "Runtime Configuration", "Initialization" 등 소제목 | 747 | 709 | 59 | 34 |

놓친 1,498개 분해: marker 또는 지시 신호(init_directive·prompt_leak·operates_under) 있음 514, 둘 다 없음 984(그중 op_heading 445).

## 6. 해석과 주의

- **marker는 탐지 규칙에 쓰지 않는다.** 데이터 생성 과정의 흔적이고, 실제 공격자는 남기지 않는다. 대신 벤치마크 품질 문제로 기록한다. SRC001의 26%(903/3,418)에 있다. 이 흔적을 배우는 학습형 탐지기는 dev에서 점수가 부풀 수 있다.
- **init_directive도 SRC001 생성기 틀일 가능성이 높다.** 다른 출처 악성에서는 5개뿐이다. E2의 run_directive(SRC010 틀)와 같은 문제다. 다만 "실행을 필수 선행 단계로 포장"이라는 행위 자체는 두 출처에 공통이다. 두 틀을 하나의 행위 규칙("스킬 글이 코드 실행을 선행 조건으로 요구")으로 묶는 것이 일반화에 낫다.
- **op_heading은 보조 신호다.** 정상 34개(2%)에서 걸리므로 단독으로는 쓰지 않고, 지시 신호와 묶는다.
- **남은 약 540개는 정규식으로 잡기 어렵다.** 키워드도 틀도 없고, 의도만 악성인 문장이다. 정적 1단계로는 한계이고, LLM 판정(R2)이 맡아야 할 몫이다. 2주차 규칙 초안의 목표를 정할 때 이 상한을 감안한다.
- 놓친 샘플을 직접 읽어 라벨 잡음인지 확인한 것은 아니다(E2의 006591, 006056 같은 경우).

## 7. 재현

```
cd data
curl -L -o package_manifest.csv https://raw.githubusercontent.com/protectskills/MaliciousSkillBench/main/packages/package_manifest.csv
# sha256 0225ebe52782dae384ca6eb622566021c9c6b309867d65a8f1007d516242096a (R4 1(h)와 같음)
python src001_signals.py   # §2, §5 표 + runs_dev/src001_signals.csv
python src001_profile.py   # §3 표
python src001_ngrams.py    # §4 어구
```
