# skillsplit

**Textrap** 팀 · 2026 하반기 SW·AI융합연구개발 일반과제 (한양대 ERICA SW중심대학사업단)

AI 에이전트 스킬(SKILL.md + 스크립트)의 악성 여부를 두 단계로 검사하고, **두 단계를 따로 돌려 각각 무엇을 잡고 무엇을 놓치는지 잰다.**

- **1단계** 정적 규칙: 스크립트와 SKILL.md에서 위험 패턴을 정규식(선택: AST)으로 탐지
- **2단계** LLM 판정: SKILL.md의 자연어 지시에서 프롬프트 인젝션·권한 상승 유도·사용자 은폐 지시를 판정

두 단계 결합은 새 방법이 아니다(SkillGate, SkillSieve, BIV 등). 이 저장소의 목적은 같은 질문을 **공개 벤치마크에서 실제/합성 샘플과 공격 벡터(CI/PI/MIXED)를 나눈 조건으로, 두 단계를 독립 실행해** 다시 묻는 것이다.

## 처음이면

1. `docs/study-guide.md` — 과제가 무엇이고 왜 하는지. 20분
2. 자기 파트의 가이드 — `docs/stage1-guide.md` / `docs/stage2-guide.md` / `docs/baselines.md`
3. `docs/data-format.md` — 모두가 지켜야 하는 파일 규약 (manifest, predictions.csv)
4. `docs/data.md` — 어떤 데이터를 왜 쓰나

## 구조

```
skillsplit/
  data/
    build_manifest.py     세 벤치마크 → data/manifest.csv (+ .sha256)
    manifest.csv          23,204행. 스킬 ID, 라벨, 실제/합성, 벡터, 분할  (커밋함)
    raw/                  벤치마크 원본 (커밋하지 않음. docs/data.md 참조)
  skillsplit/
    stage1/               정적 규칙 탐지기: rules.yaml, scan.py, ast_shell.py
    stage2/               LLM 판정기: judge.py, prompts/
  baselines/              기성 스캐너(cisco, SkillSpector, SkillFortify, SkillGate) 실행기
  eval/evaluate.py        manifest + predictions.csv → PR-AUC, FPR 1% 재현율, 합집합·교집합 표
  runs/                   예측 파일과 캐시 (커밋하지 않음)
  tests/                  pytest
  docs/                   가이드, 조사 보고서(docs/research/)
```

## 빠른 시작

```bash
pip install -r requirements.txt
python data/build_manifest.py                         # data/raw/가 준비된 뒤
python -m skillsplit.stage1.scan --manifest data/manifest.csv --rules skillsplit/stage1/rules.yaml --out runs/stage1_v0.csv --limit 50
python -m skillsplit.stage2.judge --manifest data/manifest.csv --prompt skillsplit/stage2/prompts/judge_v1.md --model gpt-5.4-mini --out runs/stage2_v0.csv --limit 20 --dry-run
python eval/evaluate.py --manifest data/manifest.csv --pred stage1=runs/stage1_v0.csv --pred stage2=runs/stage2_v0.csv --split dev
python -m pytest -q
```

## 규칙 세 줄

- `test` 분할은 5주차 최종 평가 때 한 번만 본다. 규칙과 프롬프트는 `dev`에서만 고친다
- 예측 파일은 `docs/data-format.md`의 형식 그대로. 점수는 0~1 연속값
- API 키, `data/raw/`, `runs/`는 커밋하지 않는다

## 팀

윤세훈(대표, 데이터·평가·문서), 오준서, 왕민 — 한양대 ERICA 인공지능학과

## 라이선스

코드 MIT. 데이터는 각 벤치마크의 조건을 따른다(`docs/data.md`).
