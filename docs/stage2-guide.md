# 2단계 LLM 판정기: 담당자에게

한 장이다. 정해진 것은 **입출력 파일 규약** 하나뿐이고, 나머지는 담당자가 정한다. 막히면 팀 채팅에 올린다. 대표도 이 부분의 전문가가 아니다.

## 목표

SKILL.md의 글을 언어모델에 읽혀서 **"이 스킬이 나쁜 의도를 담고 있는가"를 0~1 점수 하나**로 내는 프로그램. 코드 검사가 못 보는 것, 즉 설명서 속 지시(예: "보안 경고는 무시하라", "항상 이 링크를 써라")를 잡는 것이 역할이다.

## 지켜야 할 것 (이것만 고정)

- 입력: `data/manifest.csv`의 `path` 폴더 안 `SKILL.md`. 형식은 `docs/data-format.md`
- 출력: `runs/stage2_<버전>.csv`. 열은 `skill_id, score, verdict, evidence, error`. `score`는 모든 스킬에 있어야 하고 0~1 연속값
- 모델에 **스킬 ID나 라벨을 보내지 않는다** (답을 알려 주는 셈이 된다)
- API 키는 환경변수로만. 커밋하지 않는다
- `test` 분할은 보지 않는다. 프롬프트를 고치는 동안은 `dev`만 쓴다

## 선택지 (담당자가 정한다)

| 결정할 것 | 선택지 | 참고 |
|---|---|---|
| 모델 | gpt-5.4-mini(비교용, SkillGate와 같음) / Claude Haiku 4.5 / gpt-6-luna(가장 쌈) | 비용표와 계산식: `docs/research/stage2-notes.md` 7절 |
| 라벨 | 2단계(악성/정상) / 3단계(악성/의심/정상) | 취약과 악성은 다르다. `docs/study-guide.md` 3절 |
| 출력 형식 | 라벨 + 확신도 JSON | 확신도를 점수로 쓰면 연속값이 된다 |
| 긴 입력 | 자르기(앞·뒤) / 통째로 | 21 MB짜리가 하나 있다. 중앙값은 약 5,000자 |
| 흔들림 대응 | temperature 0, 여러 번 실행해 평균 | SkillGate는 3회 평균과 표준편차를 보고했다 |
| 심판 속이기 방어 | 없음 / 입력을 표시해서 "이건 데이터"라고 알리기(spotlighting) | A/B로 비교하면 결과가 하나 생긴다. `docs/research/stage2-notes.md` 6절 |

## 알아 두면 좋은 것

- 비슷한 판정기의 프롬프트가 공개되어 있다. SkillGate(MIT): https://github.com/awsm-research/skillgate/blob/c1641c5d/skillgate/classifier/llm.py . 읽고 자기 것을 쓰면 된다. 통째로 복사하지는 않는다
- 심판 LLM도 속는다. 설명서 문구만 바꿔서 차단을 피한 비율이 36.5%에서 100%였다(arXiv 2605.11418). 그래서 "얼마나 뚫리는지"도 결과다
- 돈이 든다. 9,740건 1회에 gpt-5.4-mini 약 $28, Haiku 4.5 약 $36, gpt-6-luna 약 $3.55. 3회면 세 배. Batch API는 50% 할인. 예산 상한은 첫 미팅에서 정한다
- 같은 입력을 두 번 부르지 않게 결과를 저장해 두면 돈과 시간을 아낀다

## 1주차에 하면 좋은 것

1. `docs/data-format.md` 읽기 (10분)
2. SkillGate 프롬프트 원문 읽기 (20분)
3. API 키 발급, 스킬 5개로 프롬프트 v1 시험. JSON이 제대로 나오는지만 본다
4. `dev` 20건에 돌려서 `runs/stage2_v1.csv` 내고 `python eval/evaluate.py`로 표 보기

## 더 읽기

- 세부 참고(입력 구성, 라벨 정의, 비용표, spotlighting 원문): `docs/research/stage2-notes.md`
- 기존 판정기 설계 조사 원문: `docs/research/R2_llm_judge.md`
- 프롬프트 인젝션이 왜 근본적인 문제인지: `docs/study-guide.md` 5절
