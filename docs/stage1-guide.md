# 1단계 정적 탐지기: 담당자에게

한 장이다. 정해진 것은 **입출력 파일 규약** 하나뿐이고, 나머지는 담당자가 정한다. 막히면 대표에게 묻지 말고 팀 채팅에 올린다. 대표도 이 부분의 전문가가 아니다.

## 목표

스킬 폴더(SKILL.md + 스크립트)를 읽어서 **"얼마나 악성 같은가"를 0~1 점수 하나**로 내는 프로그램. 코드 실행은 절대 하지 않는다. 읽기만 한다.

## 지켜야 할 것 (이것만 고정)

- 입력: `data/manifest.csv`의 `path` 열이 가리키는 폴더. 형식은 `docs/data-format.md`
- 출력: `runs/stage1_<버전>.csv`. 열은 `skill_id, score, verdict, evidence, error`. `score`는 모든 스킬에 있어야 하고 0~1 연속값
- `test` 분할은 보지 않는다. 규칙을 고치는 동안은 `dev`만 쓴다
- 규칙을 남의 것에서 가져오면 출처와 라이선스를 적는다. AGPL(trufflehog)과 GPL(bashlex)은 쓰지 않는다

## 선택지 (담당자가 정한다)

| 결정할 것 | 선택지 | 참고 |
|---|---|---|
| 무엇을 읽나 | 스크립트만 / SKILL.md도 | ClawHavoc의 설치 명령은 SKILL.md 안에 있었다. `docs/study-guide.md` 2절 |
| 어떻게 찾나 | 정규식 / AST(tree-sitter) / 둘 다 | 정규식은 `c${u}rl` 같은 우회에 약하다. `docs/research/stage1-notes.md` 6절 |
| 규칙을 어디서 가져오나 | SkillGate(MIT), Cisco 규칙 팩(MIT), SkillSpector(Apache), gitleaks(MIT), Sigma(DRL) | 출처·라이선스·URL 표: `docs/research/R1_static_rules.md` |
| 점수를 어떻게 만드나 | 최대 심각도 / 가중 합 / 그 외 | 0과 1만 내면 지표(PR-AUC)가 안 나온다. 값이 여러 단계여야 한다 |

## 알아 두면 좋은 것

- 참고 실행 하나가 있다. 공개 규칙 59개를 모아 돌렸더니 합성 샘플에서는 잘 잡히고(PR-AUC 0.92) 실제 샘플에서는 무너졌다(0.39). 정상 스킬의 설치 안내 속 `curl | sh`, AWS 스킬의 `~/.aws` 경로가 오탐이었다. 같은 패턴이 정상에도 있다는 뜻이다. 볼트 `wiki/experiments/E-01`. 그 코드는 `reference/claude-v0` 브랜치에만 있고 보지 않아도 된다
- 21 MB짜리 SKILL.md가 벤치마크에 하나 있다. 큰 파일을 어떻게 할지 정해 둔다
- 실제 악성 샘플은 백신이 지운다. 작업 환경은 첫 미팅에서 정한다. `docs/data.md` 5절

## 1주차에 하면 좋은 것

1. `docs/data-format.md` 읽기 (10분)
2. `data/raw/`의 스킬 폴더를 몇 개 열어 보기. 악성 하나, 정상 하나
3. 규칙 출처 중 하나를 골라 규칙 10개로 시작하는 가장 작은 스캐너 만들기
4. `dev` 50건에 돌려서 `runs/stage1_v1.csv` 내고 `python eval/evaluate.py`로 표 보기

## 더 읽기

- 세부 참고(규칙 가족, 출처 표, AST 예, 관찰된 오탐 유형): `docs/research/stage1-notes.md`
- 규칙 출처 조사 원문: `docs/research/R1_static_rules.md`
- 비슷한 도구의 논문: SkillGate https://arxiv.org/abs/2607.25619 (규칙만 / LLM만 / 결합을 나눠 잰 Table VI)
