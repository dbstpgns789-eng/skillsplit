# stage1 — 정적 탐지기 (담당: 왕민)

SKILL.md를 규칙으로 검사해 악성 점수(0~1)와 걸린 규칙을 낸다. 정규식만 쓴다. 4주차에 계획했던 AST는 dev에서 더 잡을 수 있는 몫의 상한이 악성 6개라 붙이지 않았다([E6](../../docs/experiments/E6_stage1_v1.md) §6). v1이 동결 후보다.

설계 근거는 [R1](../../docs/research/R1_static_rules.md)(규칙 출처·라이선스), [E1](../../docs/experiments/E1_baselines_dev.md)(기존 도구 기준선), [E2](../../docs/experiments/E2_missed_cases.md)·[E3](../../docs/experiments/E3_src001_missed.md)·[E4](../../docs/experiments/E4_residual_label_check.md)(기존 도구가 놓친 악성)다. dev 결과는 [E5](../../docs/experiments/E5_stage1_v0.md)(v0), [E6](../../docs/experiments/E6_stage1_v1.md)(v1).

## 1. 구조

```
skillsplit/stage1/
  rules.py    규칙 목록 Rule(id, severity, scope, pattern, requires, source, exclude)
  scan.py     SKILL.md → 영역 나누기 → 규칙 적용 → 점수 → jsonl 출력
data/
  s1_rule_report.py   dev에서 규칙별 집계 → 채택 판단
  s1_eval.py          입력 확인(파일 수·sha256) + 재현율·오탐률 분자/분모, 출처별, script-only 제외 (dev·test 공용)
  run_template.py     RUN_CMD·RUN_INIT 걸린 줄의 반복 틀 세기 (E6 §3)
  script_only.py      script-only 판정 1단계: 동봉 코드의 공격 동작 근거 (E6 §8)
  case_excerpt.py     사례 판정용 가린 발췌 (E6 §5)
tests/
  test_stage1.py      규칙·영역·점수·안전장치 테스트
```

- 입력: 스킬 폴더 경로(그 아래 `<id>/SKILL.md`).
- 출력: 한 줄에 `{"skill_id": benchmark_id, "score": 0~1, "evidence": ["RULE@L42", ...]}` (2026-10-12 결정, 2단계와 같은 형식). 부가 정보(`oversize`, `scanned_chars`, `empty`)는 `.details.jsonl`에 따로 쓴다.
- 스킬 목록·읽기·결과 쓰기는 `stage2/common.py`의 `list_skills`, `read_skill`, `write_result`, `append_jsonl`을 import해서 쓴다. 두 단계가 같은 입력을 받게 하기 위함이다. `stage2` 파일은 고치지 않는다.

## 2. 규칙

채택은 §4 절차로 dev에서 재서 정한다. 가중치는 CRITICAL 0.9, HIGH 0.7, MEDIUM 0.4, LOW 0.2.

범위(scope): `frontmatter`(맨 앞 `---` 블록), `prose`(코드 블록 밖), `code`(코드 블록 안, 언어 무관), `all`(문서 전체).

### 2.1 산문 규칙 (E2~E4에서 나온 것)

"노리는 공격 유형"은 규칙의 목표를 설명한 것이고 정규식 자체가 아니다. 정규식은 정해 둔 단어 목록과 구조(예: 출력 동사 + 일정 거리 안의 "시작 때 받은 지시" 명사)에 맞는 표현만 잡는다. 같은 뜻을 목록에 없는 단어나 다른 언어로 쓰면 놓친다. 의미 판단은 2단계 몫이다.

| id | 심각도 | 범위 | 노리는 공격 유형 | 정규식 상태 |
|---|---|---|---|---|
| RUN_CMD | HIGH | prose | 로컬 스크립트 실행 명령(`` `python x` ``)을 필수·선행 단계로 요구 | 기존 (E2 `signals.py` run_directive) |
| RUN_INIT | HIGH | prose | "초기화 스크립트·단계"를 먼저 실행하라고 요구 | 기존 (E3 `src001_signals.py` init_directive) |
| PROMPT_LEAK | HIGH | prose | 시작 때 받은 지시문·시스템 프롬프트를 출력·전사하라 | 기존 (E3 `src001_signals.py` prompt_leak). 넓히지 않음 |
| OVERRIDE | HIGH | prose | 이전 지침·안전 장치를 무효로 하라, 제한 없이 동작하라 | 새로 작성 (E4 유형) |
| LURE | HIGH | prose | 비밀번호 걸린 압축 파일, 붙여넣기 사이트, 터미널에 붙여넣기 | 기존 (E2 `signals.py` lure) |
| HOMOGLYPH | HIGH | all | 한 단어 안에 라틴 + 키릴·그리스 문자 | 기존 (E2 `signals.py` homoglyph) |
| RECON_DUMP | MEDIUM | prose | 첫 답으로 파일 목록·권한·계정·환경 정보를 정리해 내라 | 새로 작성 (E4 유형) |
| HIDDEN_DIRECTIVE | MEDIUM | all | HTML 주석 안에 에이전트에게 하는 지시 | 새로 작성 (E4 유형) |
| PERSONA_LOCK | MEDIUM | prose | 특정 인물로만 행세하고 AI임을 인정하지 말라 | 새로 작성 (E4 유형) |
| CONCEAL | MEDIUM | prose | 사용자에게 알리지 말라, 몰래 실행하라. **결합 전용**: 산문 HIGH 규칙이 함께 걸릴 때만 | 기존 (E2 `signals.py` conceal) |
| DESC_BYPASS | LOW | frontmatter | description에 bypass·unrestricted 등. **결합 전용**: 다른 규칙이 함께 걸릴 때만 | 기존 (E2 `signals.py` desc_bypass) |

### 2.2 코드 블록 규칙 (기존 도구에서 결합형만 옮김)

| id | 심각도 | 노리는 공격 유형 | 정규식 출처 (R1 §8) |
|---|---|---|---|
| PIPE_TO_SHELL | CRITICAL | 내려받은 내용을 바로 셸로 넘김 | SkillGate RCE001~004 (MIT) |
| DECODE_EXEC | CRITICAL | 같은 코드 블록에서 base64 디코드 + eval/exec | SkillGate RCE010~012 (MIT), SkillSpector SC3 (Apache-2.0) |
| REMOTE_EXEC | CRITICAL | 원격에서 받은 내용을 그대로 실행 | SkillSpector (Apache-2.0), Cisco (Apache-2.0) |
| CRED_PATH | HIGH | 자격증명 경로 접근. 키 문자열은 보지 않음. `ssh-add`·`ssh-keygen`·`ssh -i`로 시작하는 줄은 제외(v1, `exclude`). 같은 줄에 `;`·`&`·`|`로 다른 명령이 붙으면 제외하지 않음 | SkillGate CRED001~019 (MIT) |
| EXFIL_SEND | HIGH | 파일·환경변수를 밖으로 전송 | SkillGate EXFIL (MIT), SkillSpector E1 (Apache-2.0) |
| PERSISTENCE | HIGH | crontab, 셸 시작 파일에 덧붙이기, launchctl, systemd | SkillGate PRIV 계열 (MIT), E4 |

다른 저장소의 정규식을 그대로 옮기거나 고쳐 쓴 규칙은 `source`에 저장소·규칙 id·라이선스를 남기고, 저장소 루트 `THIRD_PARTY_LICENSES.md`에 고지를 적는다(R1 §9).

### 2.3 넣지 않는 것

- 벤치마크 생성기 흔적(`scripts/_x.py`, "original SKILL.md"): 2026-10-08 결정.
- 단일 명령 규칙(SkillGate CMD001 `curl`)과 키 문자열 규칙(CRED014): E1에서 정상과 구분하지 못함.
- SkillGate CMD033(`cat` 민감 경로), RCE009(`$(cat /경로)`), DISC101(`env` 덤프): 소수 출처에서 더 잡지만 새로 잡는 몫이 정상 오탐과 같은 형태(E6 §5).
- 영어 외 언어의 지시문, 답 편향 지시: v0 범위 밖. 2단계 몫.

## 3. 점수와 예외 처리

### 3.1 점수

- `score = 1 − Π(1 − w_r)`, 걸린 규칙마다 한 번(noisy-OR). 예: HIGH 하나 0.7, HIGH 둘 0.91, CRITICAL + MEDIUM 0.94. 안 걸리면 0.
- 심각도 등급 기준: CRITICAL = 내려받거나 디코드한 코드를 바로 실행, HIGH = 혼자서도 공격 의도가 드러나는 지시·위장(한 단어 안에 다른 문자 섞기)·자격증명·유출·지속성, MEDIUM = 정상 문서에도 나올 수 있어 맥락이 필요한 것, LOW = 결합 전용 보조. 17개 규칙은 CONCEAL을 빼고 이 기준과 맞는다(§2 표). CONCEAL은 결합 전용이지만 산문 HIGH 규칙과 짝을 이룰 때만 발동하므로 MEDIUM으로 둔다.
- 가중치 값(0.9/0.7/0.4/0.2)은 등급 순서만 반영한 임의 값이고, v0 때 정한 이유는 남기지 않았다. score > 0 기준에서는 등급과 값이 걸림 여부를 바꾸지 않는다. 모두 0.7로 같게 해도 dev 전체 PR-AUC는 v0 0.9064 → 0.9061, v1 0.9072 → 0.9070이고 dev100은 0.820 그대로다(`s1_rule_report.py`). v0에서 걸린 샘플 3,674개 중 정상이 21개뿐이라, 걸린 샘플끼리의 순서가 PR-AUC를 거의 바꾸지 않는다.
- 결합 전용 규칙은 짝이 걸렸을 때만 점수와 evidence에 들어간다.
- evidence는 `"RULE@L줄번호"`, 심각도 높은 순 → 줄 순. 규칙마다 최대 3줄.
- **걸림 기준은 score > 0**이다(2026-10-12 결정, 동결 때 유지). 발동한 규칙이 하나라도 있으면 걸림이고, 결합 전용 규칙은 짝이 있어야 발동한다. 가중치가 쌓여야 걸리는 구조가 아니다. 가중치는 모두 양수라 값을 바꿔도 걸림 여부(재현율·오탐률)는 바뀌지 않고, 걸린 샘플끼리의 순서(PR-AUC)만 바뀐다.

### 3.2 SKILL.md 나누기

- frontmatter: 파일 맨 앞 `---` 줄부터 다음 `---` 줄까지.
- 코드 블록: ```` ``` ```` 또는 `~~~` 펜스. 닫히지 않으면 파일 끝까지 코드.
- 산문: 나머지.
- 줄 번호 유지: 대상이 아닌 영역은 줄바꿈만 남기고 공백으로 덮은 같은 길이의 문자열에 규칙을 적용한다. 걸린 위치가 곧 원문 위치다.

### 3.3 예외

| 상황 | 처리 | 이유 |
|---|---|---|
| 200,000자 초과 | details에 `oversize=true`, 앞 300,000자만 검사, `scanned_chars` 기록 | R2 §3의 oversize 기준을 2단계와 같이 씀 |
| 정규식 폭주 | `.*` 룩어헤드·중첩 반복 금지, 사이 간격은 `{0,120}`처럼 상한. 20MB 한 줄 테스트 | E1 §3-3 (SkillGate가 20MiB 한 줄에서 멈춤) |
| 규칙 정규식 컴파일 실패 | import 때 바로 오류 | E1 §3-1 (SkillGate는 3개를 조용히 뺌) |
| 인코딩 | `stage2/common.read_skill` 그대로 | 2단계와 같은 입력 |
| 빈 SKILL.md | score 0, details `empty=true` | |

zero-width 문자 제거나 유니코드 정규화는 하지 않는다(v1도 같음).

## 4. 규칙 채택 절차 (`data/s1_rule_report.py`)

규칙 선택은 dev 전체(8,348)로 한다. dev100은 2단계와 비교할 때만 쓴다(2026-10-12 결정). test는 쓰지 않는다.

규칙별 집계: 악성 적중 수, 정상 적중 수·비율, 악성이 3건 이상 걸린 출처 수, 최다 출처 비중, Cisco·SkillGate가 둘 다 놓친 악성 중 새로 잡은 수.

채택 기준, 순서대로:

1. 정상 적중률 ≤ 1% → 단독 규칙. 넘으면 결합 전용으로 바꾸거나 뺀다.
2. 악성 출처 ≥ 2개(각 3건 이상) **그리고** 최다 출처 비중 < 90% → 채택. 아니면 "출처 편향" 표시를 달고 채택하며, 재현율을 편향 규칙 포함·제외 두 가지로 보고한다. 비중 상한은 4주차에 더했다. dev 악성의 93%가 SRC001·SRC010이라 출처 수만으로는 한 출처에 맞춘 규칙이 걸러지지 않았다(E6 §3).
3. 전체: dev 정상 오탐률(score > 0) ≤ 2%. 넘으면 정밀도가 가장 낮은 규칙부터 뺀다.

보고 지표: score > 0 기준 재현율·오탐률(주 지표), 재현율은 전체(기본 보고)와 script-only 제외(표본으로 낸 보조 추정값, 기준은 E6 §8.2·`docs/script_only_proposal.md`) 두 가지, 출처별 재현율, Cisco와의 네 칸, dev100 수치. PR-AUC는 같은 데이터에서 다른 탐지기와 비교할 때만 쓴다. 정적은 안 걸리면 0점이라, 아무것도 못 잡아도 PR-AUC가 악성 비율만큼 나오기 때문이다(PR #4 리뷰). 결과는 `docs/experiments/E5_stage1_v0.md`(v0), `E6_stage1_v1.md`(v1), 동결 자료는 `docs/stage1_freeze.md`. 동결 때 채택 규칙 목록을 `docs/decisions.md`에 한 줄로 남긴다.

## 5. 테스트 (`tests/test_stage1.py`, pytest)

- 규칙별: 걸려야 하는 합성 문장 하나, 안 걸려야 하는 문장 하나. 실제 악성 원문은 쓰지 않고, 직접 쓴 무해한 문장과 `example.invalid` 같은 가짜 주소만 쓴다.
- 영역: frontmatter, 언어별 코드 블록, 닫히지 않은 코드 블록, 줄 번호가 원문과 일치.
- 점수: noisy-OR 값, 결합 전용 규칙이 혼자서는 발동하지 않음.
- 예외: `exclude`에 맞는 줄만 빠지고 같은 파일의 다른 줄은 걸림.
- 안전장치: 모든 정규식 컴파일, 20MB 한 줄 문자열을 5초 안에 처리.

## 6. 일정

| 주차 | 할 일 |
|---|---|
| 3주차 | 구현, 테스트, dev 전체 규칙 보고서, dev100 결과(공통 형식) |
| 4주차 | 규칙 조정(RUN_DIRECTIVE 나누기, CRED_PATH 예외, 기준 2 비중 상한), v1 동결. AST는 재 보고 생략(E6) |
