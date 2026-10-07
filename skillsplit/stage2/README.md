# stage2 — 설명서 판정기 (담당: 오준서)

SKILL.md의 자연어를 읽고 악성일 가능성을 0~1 점수로 낸다. 두 버전이 있다.

| 버전 | 파일 | 어떻게 판단하나 | 점수 |
|---|---|---|---|
| LLM | `llm_judge.py` + `prompt_v0.txt` | LLM이 SAFE / SUSPICIOUS / MALICIOUS와 확신도, 근거 인용을 JSON으로 답한다 | 라벨 구간 + 확신도 (`to_score`) |
| Jev | `jev_judge.py` + `jev_questions_v0.json` | Jev가 정해진 질문 세 개에 확률로 답한다 | `is_malicious` 확률 그대로 |

두 버전은 같은 입력 처리(`common.py`: 읽기, 자르기)를 쓴다.

## Jev를 어디에 어떻게 쓰나

**위치.** Jev는 2단계(설명서 판정기)의 두 번째 버전이다. 1단계(정적 탐지기)와는 따로, LLM 버전과는 나란히 돈다. 두 버전은 같은 스킬을 같은 입력 처리(`common.py`)로 받는다.

```
1단계 정적 탐지기 ─────────────────────┐
2단계 설명서 판정기 ─┬─ LLM 버전 (Claude) ─┼─▶ 채점 → 성적표
                    └─ Jev 버전          ─┘
```

**왜 쓰나.**
1. 재현 비교: jev-skillbench가 MalSkillBench에서 낸 Jev 결과(단독, 문턱 0.5: 재현율 0.755, 오탐률 0.000. 개인 저장소, 동료 심사 없음)를 같은 질문으로 MaliciousSkillBench에서 다시 잰다.
2. 성격 비교: 말로 판단하는 LLM과 확률만 내는 판정 전용 모델 중 어느 쪽이 무엇을 잘 잡는가.
3. 사례 분석: LLM 버전과 Jev 버전이 엇갈린 스킬을 들여다본다.

**무엇을 묻나.** `jev_questions_v0.json`의 질문 세 개(jev-skillbench에서 그대로 옮김). 점수는 `is_malicious` 확률, evidence는 `attack_vector`와 `harm_severity` 답.

**언제.**

| 주차 | Jev로 할 일 |
|---|---|
| 1 | 접근 확보 (완료, 2026-10-07) |
| 2 | dev100 전체를 Jev로 판정해 LLM 버전과 비교 |
| 3~4 | dev로 점검. 질문 문장을 바꾸면 재현 비교가 깨지므로 v0 유지가 기본, 바꾸면 v1로 따로 기록 |
| 4 끝 | 동결 |
| 5 | held-out 1회 판정 → 성적표의 "2단계-Jev" 줄, 네 칸 분해, 엇갈린 사례 |

**접근.** Vercel AI Gateway, 모델 `typesafe-ai/jev`, 키는 환경변수 `AI_GATEWAY_API_KEY`(코드나 저장소에 넣지 않는다). 카드 등록과 유료 크레딧이 필요하다(Jev는 무료 등급 모델이 아님). 가격 입력 100만 토큰당 $0.042, 출력 무료. 1건 측정값 약 2,400토큰·$0.0001·1.1초라 held-out 1,384건은 약 $0.15로 예상.

**주의.**
- Jev는 내부 구조가 공개되지 않아 왜 그렇게 판정했는지 알 수 없다. 사례 분석의 "이유"는 LLM 버전의 근거와 Jev의 `attack_vector` 답으로 대신한다.
- 입력에 `benchmark_id`, 출처를 넣지 않는다(라벨 누출 방지). Jev 입력 한도 32k 토큰은 공통 자르기 규칙으로 지킨다.
- jev-skillbench의 네 번째 질문(behavior)은 점수에 쓰이지 않아 v0에서 뺐다.

## 출력 (팀 공통 형식)

`--out`으로 준 파일에 한 줄에 한 스킬:

```json
{"skill_id": "ASB04_000247", "score": 0.9933, "evidence": ["원문에서 그대로 옮긴 구절"]}
```

같은 이름의 `.details.jsonl`에 판정기만의 정보(모델, 라벨, 확신도, 거부, 파싱 실패, 자른 글자 수, 토큰, 시간)가 남는다.

## 돌리기

```bash
pip install anthropic           # LLM 버전 (api)
# data/README.md 순서대로 data/dev100 을 먼저 만든다

# LLM 버전, Anthropic API (최종 측정용)
export ANTHROPIC_API_KEY=...
python -m skillsplit.stage2.llm_judge data/dev100 --out runs/stage2_llm_v0_dev100.jsonl

# LLM 버전, 로컬 claude CLI (API 키 없이 코드 점검용. 재현성이 약해 보고서 수치로 쓰지 않음)
python -m skillsplit.stage2.llm_judge data/dev100 --out runs/smoke.jsonl --backend cli --limit 5

# Jev 버전 (Vercel AI Gateway 경유)
export AI_GATEWAY_API_KEY=...
python -m skillsplit.stage2.jev_judge data/dev100 --out runs/stage2_jev_v0_dev100.jsonl --via vercel --limit 1
```

중간에 끊겨도 같은 `--out`으로 다시 돌리면 이미 끝난 스킬은 건너뛴다.

## v0에서 정한 것과 근거

| 항목 | 값 | 근거 |
|---|---|---|
| 자르기 | 12,000자 초과 시 머리 8,000 + 꼬리 4,000 | `docs/research/R2_llm_judge.md` C1, SkillGate 코드 |
| 프롬프트 | SkillGate 시스템 프롬프트를 SKILL.md 단독 입력에 맞게 고침 + 기능-행동 일치 질문 + 결함은 악성 아님 + 근거 인용 | R2 A1, C2, C3 |
| 인젝션 방어 | `<<<SKILL_MD_BEGIN>>>` 구분자, 안의 지시 무시, 판정 조작 시도는 악성 신호 | R2 A5, C7 조건 A (Spotlighting delimiting) |
| 모델 | `claude-haiku-4-5`, temperature 0 | R2 C4, C5 |
| 파싱 실패·거부 | SUSPICIOUS 0.4 (fail-closed), details에 표시 | R2 C3 |
| 근거 검사 | 원문에 없는 인용은 버리고 개수를 기록 | R2 C3 |
| 입력에서 뺀 것 | `benchmark_id`, `source_id`, 스킬 폴더 이름 | 라벨 누출 방지 (R2 C1-5) |
| Jev 질문 | jev-skillbench의 is_malicious, attack_vector, harm_severity | 기존 결과를 다른 데이터에서 재현 |

## 아직 안 한 것

- Anthropic API 실행 (키 필요, 또는 Vercel 키로 Claude 호출 가능한지 확인), Jev로 dev100 전체
- 결과 캐시(SQLite, R2 C6), 3회 반복 실행, Spotlighting B 조건 (2주차 이후)
- 점수 문턱 θ와 거부 처리 규칙 확정 (4주차)
