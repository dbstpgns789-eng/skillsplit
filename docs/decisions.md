# 결정 기록

한 줄에 하나. 날짜 · 결정 · 이유 · 근거 문서. 다른 팀원의 작업이나 최종 숫자에 영향을 주는 결정만 적는다.

- 2026-10-07 · SkillGate 규칙 수는 "530개(저장소 533개 중 3개는 컴파일 실패로 로드 안 됨)"로 쓴다 · 논문 수치와 실제 동작이 일치함을 확인 · [E1](experiments/E1_baselines_dev.md) §3
- 2026-10-07 · SkillGate 기준선은 `awsm-research/skillgate@c1641c5`, 규칙만(LLM 끔)으로 돌린다 · 논문 Table VI "규칙만" 조건과 같음 · [E1](experiments/E1_baselines_dev.md) §1
- 2026-10-07 · (제안, 데이터·평가 담당 확인 필요) Cisco 기준선은 `cisco-ai-skill-scanner==2.2.1`에 `--use-behavioral`(논문의 local-behavioral 설정)을 기본으로 쓰고, 기본 설정 결과도 함께 남긴다 · 논문과 같은 설정으로 비교하기 위함. dev에서 두 설정 차이는 재현율 +0.2%p · [E1](experiments/E1_baselines_dev.md) §2
- 2026-10-07 · 스캐너가 샘플당 60초를 넘기면 "스캔 실패"로 기록하고 지표에서 빼며, 실패 수를 따로 보고한다. 단, 일부 규칙만으로 "걸림"이 확인되면(OR 판정이라 결과가 바뀌지 않음) 그 판정으로 채우고 근거를 남긴다 · 20MiB 한 줄 샘플에서 SkillGate가 끝나지 않음, attack 규칙만으로 CRED014 확인 · [E1](experiments/E1_baselines_dev.md) §3
- 2026-10-08 · 벤치마크 생성기 흔적(밑줄 스크립트명 `scripts/_x.py`, "original SKILL.md" 경계 표시)은 탐지 규칙에 쓰지 않고, 평가 때 출처별 수치를 함께 보고한다 · 실제 공격자는 남기지 않는 흔적이라 dev 점수만 부풀림. 공식 분할은 test를 dev에 없는 출처로 구성하므로 한 출처에 치우친 신호는 일반화를 보장하지 않음 · [E2](experiments/E2_missed_cases.md) §4, [E3](experiments/E3_src001_missed.md) §6
- 2026-10-08 · test의 출처 구성이나 test 결과(점수·샘플별 판정)는 규칙 설계의 근거로 쓰지 않는다. 기준선의 test 결과는 5주차 평가 전까지 공유하지 않고, 실험 설정(버전·옵션)만 맞춘다 · 간접적인 test 누출로 5주차 점수가 부풀 수 있음. E2에서 test 구성을 근거로 쓴 문장을 고침 · [E2](experiments/E2_missed_cases.md) §4
