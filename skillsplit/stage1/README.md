# stage1 — 정적 탐지기 (담당: 왕민)

SKILL.md를 규칙으로 검사해 악성 점수(0~1)와 걸린 규칙을 낸다. v0은 정규식만 쓰고, 4주차 v1에서 정규식이 뚫리는 결합 규칙에만 AST(tree-sitter-bash, Python `ast`)를 붙인다.

설계 근거는 [R1](../../docs/research/R1_static_rules.md)(규칙 출처·라이선스), [E1](../../docs/experiments/E1_baselines_dev.md)(기존 도구 기준선), [E2](../../docs/experiments/E2_missed_cases.md)·[E3](../../docs/experiments/E3_src001_missed.md)·[E4](../../docs/experiments/E4_residual_label_check.md)(기존 도구가 놓친 악성)다.

## 1. 구조

```
skillsplit/stage1/
  rules.py    규칙 목록 Rule(id, severity, scope, pattern, requires, source)
  scan.py     SKILL.md → 영역 나누기 → 규칙 적용 → 점수 → jsonl 출력
data/
  s1_rule_report.py   dev에서 규칙별 집계 → 채택 판단
tests/
  test_stage1.py      규칙·영역·점수·안전장치 테스트
```

- 입력: 스킬 폴더 경로(그 아래 `<id>/SKILL.md`).
- 출력: 한 줄에 `{"skill_id": benchmark_id, "score": 0~1, "evidence": ["RULE@L42", ...]}` (2026-10-12 결정, 2단계와 같은 형식). 부가 정보(`oversize`, `scanned_chars`, `empty`)는 `.details.jsonl`에 따로 쓴다.
- 스킬 목록·읽기·결과 쓰기는 `stage2/common.py`의 `list_skills`, `read_skill`, `write_result`, `append_jsonl`을 import해서 쓴다. 두 단계가 같은 입력을 받게 하기 위함이다. `stage2` 파일은 고치지 않는다.

## 2. v0 규칙 후보

채택은 §4 절차로 dev에서 재서 정한다. 가중치는 CRITICAL 0.9, HIGH 0.7, MEDIUM 0.4, LOW 0.2.

범위(scope): `frontmatter`(맨 앞 `---` 블록), `prose`(코드 블록 밖), `code`(코드 블록 안, 언어 무관), `all`(문서 전체).

### 2.1 산문 규칙 (직접 만듦)

| id | 심각도 | 범위 | 잡는 것 | 근거 |
|---|---|---|---|---|
| RUN_DIRECTIVE | HIGH | prose | 로컬 스크립트·코드 실행을 필수·선행·초기화 단계로 요구 | E2 run_directive + E3 init_directive |
| PROMPT_LEAK | HIGH | prose | 시작 때 받은 지시문·시스템 프롬프트를 출력·전사하라 | E3 prompt_leak, E4 |
| OVERRIDE | HIGH | prose | 이전 지침·안전 장치를 무효로 하라, 제한 없이 동작하라 | E4 |
| LURE | HIGH | prose | 비밀번호 걸린 압축 파일, 붙여넣기 사이트, 터미널에 붙여넣기 | E2 lure |
| HOMOGLYPH | HIGH | all | 한 단어 안에 라틴 + 키릴·그리스 문자 | E2, E4 |
| RECON_DUMP | MEDIUM | prose | 첫 답으로 파일 목록·권한·계정·환경 정보를 정리해 내라 | E4 |
| HIDDEN_DIRECTIVE | MEDIUM | all | HTML 주석 안에 에이전트에게 하는 지시 | E4 |
| PERSONA_LOCK | MEDIUM | prose | 특정 인물로만 행세하고 AI임을 인정하지 말라 | E4 |
| CONCEAL | MEDIUM | prose | 사용자에게 알리지 말라, 몰래 실행하라. **결합 전용**: 산문 HIGH 규칙이 함께 걸릴 때만 | E2 conceal |
| DESC_BYPASS | LOW | frontmatter | description에 bypass·unrestricted 등. **결합 전용**: 다른 규칙이 함께 걸릴 때만 | E2 desc_bypass |

### 2.2 코드 블록 규칙 (기존 도구에서 결합형만 옮김)

| id | 심각도 | 잡는 것 | 출처 (R1 §8) |
|---|---|---|---|
| PIPE_TO_SHELL | CRITICAL | 내려받은 내용을 바로 셸로 넘김 | SkillGate RCE001~004 (MIT) |
| DECODE_EXEC | CRITICAL | 같은 코드 블록에서 base64 디코드 + eval/exec | SkillGate RCE010~012 (MIT), SkillSpector SC3 (Apache-2.0) |
| REMOTE_EXEC | CRITICAL | 원격에서 받은 내용을 그대로 실행 | SkillSpector (Apache-2.0), Cisco (Apache-2.0) |
| CRED_PATH | HIGH | 자격증명 경로 접근. 키 문자열은 보지 않음 | SkillGate CRED001~019 (MIT) |
| EXFIL_SEND | HIGH | 파일·환경변수를 밖으로 전송 | SkillGate EXFIL (MIT), SkillSpector E1 (Apache-2.0) |
| PERSISTENCE | HIGH | crontab, 셸 시작 파일에 덧붙이기, launchctl, systemd | SkillGate PRIV 계열 (MIT), E4 |

다른 저장소의 정규식을 그대로 옮기거나 고쳐 쓴 규칙은 `source`에 저장소·규칙 id·라이선스를 남기고, 저장소 루트 `THIRD_PARTY_LICENSES.md`에 고지를 적는다(R1 §9).

### 2.3 넣지 않는 것

- 벤치마크 생성기 흔적(`scripts/_x.py`, "original SKILL.md"): 2026-10-08 결정.
- 단일 명령 규칙(SkillGate CMD001 `curl`)과 키 문자열 규칙(CRED014): E1에서 정상과 구분하지 못함.
- 영어 외 언어의 지시문, 답 편향 지시: v0 범위 밖. 2단계 몫.

## 3. 점수와 예외 처리

### 3.1 점수

- `score = 1 − Π(1 − w_r)`, 걸린 규칙마다 한 번(noisy-OR). 예: HIGH 하나 0.7, HIGH 둘 0.91, CRITICAL + MEDIUM 0.94. 안 걸리면 0.
- 결합 전용 규칙은 짝이 걸렸을 때만 점수와 evidence에 들어간다.
- evidence는 `"RULE@L줄번호"`, 심각도 높은 순 → 줄 순. 규칙마다 최대 3줄.
- 네 칸 분해의 "걸림"은 score > 0 (2026-10-12 결정).

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

zero-width 문자 제거나 유니코드 정규화는 v0에서 하지 않는다.

## 4. 규칙 채택 절차 (`data/s1_rule_report.py`)

규칙 선택은 dev 전체(8,348)로 한다. dev100은 2단계와 비교할 때만 쓴다(2026-10-12 결정). test는 쓰지 않는다.

규칙별 집계: 악성 적중 수, 정상 적중 수·비율, 악성이 3건 이상 걸린 출처 수, 최다 출처 비중, Cisco·SkillGate가 둘 다 놓친 악성 중 새로 잡은 수.

채택 기준, 순서대로:

1. 정상 적중률 ≤ 1% → 단독 규칙. 넘으면 결합 전용으로 바꾸거나 뺀다.
2. 악성 출처 ≥ 2개(각 3건 이상) → 채택. 아니면 "출처 편향" 표시를 달고 채택하며, 재현율을 편향 규칙 포함·제외 두 가지로 보고한다.
3. 전체: dev 정상 오탐률(score > 0) ≤ 2%. 넘으면 정밀도가 가장 낮은 규칙부터 뺀다.

보고 지표: PR-AUC, score > 0 기준 재현율·오탐률, 출처별 재현율, Cisco와의 네 칸, dev100 수치. 결과는 `docs/experiments/E5_stage1_v0.md`, 동결 때 채택 규칙 목록을 `docs/decisions.md`에 한 줄로 남긴다.

## 5. 테스트 (`tests/test_stage1.py`, pytest)

- 규칙별: 걸려야 하는 합성 문장 하나, 안 걸려야 하는 문장 하나. 실제 악성 원문은 쓰지 않고, 직접 쓴 무해한 문장과 `example.invalid` 같은 가짜 주소만 쓴다.
- 영역: frontmatter, 언어별 코드 블록, 닫히지 않은 코드 블록, 줄 번호가 원문과 일치.
- 점수: noisy-OR 값, 결합 전용 규칙이 혼자서는 발동하지 않음.
- 안전장치: 모든 정규식 컴파일, 20MB 한 줄 문자열을 5초 안에 처리.

## 6. 일정

| 주차 | 할 일 |
|---|---|
| 3주차 | 구현, 테스트, dev 전체 규칙 보고서, dev100 결과(공통 형식) |
| 4주차 | 규칙 조정, v1(AST), 동결 |
