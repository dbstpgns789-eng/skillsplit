# stage2 — 설명서 판정기 (담당: 오준서)

SKILL.md의 자연어를 읽고 악성일 가능성을 0~1 점수로 낸다. 두 버전이 있다.

| 버전 | 파일 | 어떻게 판단하나 | 점수 |
|---|---|---|---|
| LLM | `llm_judge.py` + `prompt_v0.txt` | LLM이 SAFE / SUSPICIOUS / MALICIOUS와 확신도, 근거 인용을 JSON으로 답한다 | 라벨 구간 + 확신도 (`to_score`) |
| Jev | `jev_judge.py` + `jev_questions_v0.json` | Jev가 정해진 질문 세 개에 확률로 답한다 | `is_malicious` 확률 그대로 |

두 버전은 같은 입력 처리(`common.py`: 읽기, 자르기)를 쓴다.

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

- Anthropic API 실행 (키 필요), Jev 실제 호출 (접근 확보 필요)
- 결과 캐시(SQLite, R2 C6), 3회 반복 실행, Spotlighting B 조건 (2주차 이후)
- 점수 문턱 θ와 거부 처리 규칙 확정 (4주차)
