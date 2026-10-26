# E5. 정적 탐지기 v0 dev 결과

실행일 2026-10-23. 담당 정적 탐지기(왕민). 코드 커밋 `aaa35f7`(규칙 16개). dev만 사용, test는 보지 않았다. 설계는 [stage1 README](../../skillsplit/stage1/README.md).

## 0. 한 줄 결론

- dev 전체(8,348)에서 **재현율 0.549, 정상 오탐률 0.012(21/1,690), PR-AUC 0.906**이다. 오탐률 2% 기준을 통과한다.
- 같은 dev에서 Cisco 정적은 재현율 0.310·오탐률 0.008, SkillGate 규칙만은 0.422·0.253이었다([E1](E1_baselines_dev.md)). v0는 Cisco보다 재현율이 24%p 높고, 오탐률은 0.4%p 높다.
- Cisco와 네 칸(악성 6,658): 정적만 2,024, Cisco만 434, 둘 다 1,629, 둘 다 놓침 2,571.
- **출처 쏠림이 크다.** SRC010 재현율 0.771, SRC001 0.408에 비해 나머지 출처는 0.03~0.12다(SRC002 0.569 제외). 채택 기준 2번(출처 2개 이상)은 거의 모든 규칙이 통과해서, 이 쏠림을 걸러내지 못했다(§3).
- dev100: 재현율 0.640, 오탐률 0.000(0/50), PR-AUC 0.820. dev100은 악성:정상이 50:50이라 dev 전체와 PR-AUC를 비교하지 않는다(2026-10-12 결정).

## 1. 규칙별 (dev 전체)

`ben_rate`는 정상 1,690개 중 적중 비율이다. `n_sources`는 악성이 3건 이상 걸린 출처 수다. `new_vs_baselines`는 Cisco·SkillGate가 둘 다 놓친 악성 중 새로 잡은 수다.

| rule | 심각도 | 악성 적중 | 정상 적중 | ben_rate | n_sources | 최다 출처 | new_vs_baselines | status |
|---|---|---:|---:|---:|---:|---|---:|---|
| RUN_DIRECTIVE | HIGH | 2,510 | 0 | 0.0000 | 3 | SRC010 72% | 1,170 | 채택 |
| PROMPT_LEAK | HIGH | 102 | 2 | 0.0012 | 3 | SRC001 90% | 44 | 채택 |
| OVERRIDE | HIGH | 370 | 0 | 0.0000 | 2 | SRC001 52% | 92 | 채택 |
| LURE | HIGH | 164 | 1 | 0.0006 | 2 | SRC001 58% | 26 | 채택 |
| HOMOGLYPH | HIGH | 63 | 2 | 0.0012 | 2 | SRC001 92% | 38 | 채택 |
| RECON_DUMP | MEDIUM | 9 | 0 | 0.0000 | 1 | SRC001 89% | 6 | 출처 편향 |
| HIDDEN_DIRECTIVE | MEDIUM | 137 | 1 | 0.0006 | 2 | SRC001 53% | 56 | 채택 |
| PERSONA_LOCK | MEDIUM | 3 | 0 | 0.0000 | 1 | SRC001 100% | 3 | 출처 편향 |
| CONCEAL (결합 전용) | MEDIUM | 644 | 0 | 0.0000 | 1 | SRC010 100% | 132 | 출처 편향 |
| DESC_BYPASS (결합 전용) | LOW | 31 | 1 | 0.0006 | 2 | SRC010 71% | 14 | 채택 |
| PIPE_TO_SHELL | CRITICAL | 336 | 1 | 0.0006 | 3 | SRC001 62% | 0 | 채택 |
| DECODE_EXEC | CRITICAL | 79 | 0 | 0.0000 | 2 | SRC001 58% | 0 | 채택 |
| REMOTE_EXEC | CRITICAL | 14 | 0 | 0.0000 | 1 | SRC001 100% | 0 | 출처 편향 |
| CRED_PATH | HIGH | 53 | 8 | 0.0047 | 2 | SRC001 91% | 0 | 채택 |
| EXFIL_SEND | HIGH | 23 | 0 | 0.0000 | 2 | SRC001 78% | 0 | 채택 |
| PERSISTENCE | HIGH | 56 | 6 | 0.0036 | 2 | SRC001 80% | 0 | 채택 |

## 2. 전체와 출처별

| 조건 | PR-AUC | 재현율 | 오탐률 |
|---|---:|---:|---:|
| dev 전체, 규칙 16개 | 0.906 | 0.549 | 0.012 (21/1,690) |
| dev 전체, 출처 편향 4개(CONCEAL, PERSONA_LOCK, RECON_DUMP, REMOTE_EXEC) 제외 | 0.906 | 0.547 | 0.012 |
| dev100 | 0.820 | 0.640 | 0.000 (0/50) |

| 출처 | 악성 n | 재현율 |
|---|---:|---:|
| SRC001 | 3,418 | 0.408 |
| SRC002 | 153 | 0.569 |
| SRC004 | 33 | 0.121 |
| SRC005 | 30 | 0.100 |
| SRC006 | 86 | 0.116 |
| SRC008 | 1 | 1.000 |
| SRC010 | 2,783 | 0.771 |
| SRC013 | 154 | 0.032 |

## 3. 채택 판단 (README §4 기준)

- **기준 1(정상 적중률 ≤ 1%)**: 16개 모두 통과한다. 정상 적중이 가장 많은 것은 CRED_PATH(8)와 PERSISTENCE(6)다. 둘 다 코드 블록 규칙이고, 기존 도구가 이미 잡던 샘플만 잡는다(new_vs_baselines 0).
- **기준 2(악성 출처 ≥ 2)**: 12개 채택, 4개 출처 편향. 출처 편향 4개를 빼도 재현율이 0.002만 줄어서, 점수에는 남겨 둔다.
- **기준 3(오탐률 ≤ 2%)**: 1.2%로 통과한다. 빼야 할 규칙은 없다.
- **기준 2의 한계**: dev 악성의 93%가 SRC001과 SRC010이다. 그래서 "3건 이상 걸린 출처 2개"는 거의 항상 이 둘로 채워진다. 실제로 최다 출처 비중이 90% 이상인 규칙(PROMPT_LEAK, HOMOGLYPH, CRED_PATH)도 통과했다. RUN_DIRECTIVE가 새로 잡은 1,170개는 SRC010 881(75%), SRC001 285, 나머지 4개다. SRC010 쪽은 E2의 주입 틀일 가능성이 높다. 기준을 바꿀지(예: 최다 출처 비중 상한)는 4주차에 정한다.
- **결론**: v0 규칙 16개를 그대로 4주차 출발점으로 쓴다.

## 4. 다음 (4주차)

- 소수 출처 재현율이 낮은 이유를 찾는다: SRC013(0.032), SRC004·005·006(0.10~0.12). 지금 규칙의 단어 목록이 SRC001·SRC010 문체에 맞춰져 있을 가능성이 있다.
- RUN_DIRECTIVE를 SRC010 틀 문장과 일반 형태로 나눠 따로 센다. 출처 편향 정도를 숫자로 확인하기 위함이다.
- 정상 오탐 21개를 규칙별로 확인한다(CRED_PATH 8, PERSISTENCE 6 우선).
- v1: DECODE_EXEC, PIPE_TO_SHELL에 AST를 붙여 줄을 넘는 경우를 잡는다. 다만 코드 블록 규칙은 기존 도구와 겹치는 샘플만 잡았으므로(new_vs_baselines 0), 재현율 상승은 작을 것으로 본다.

## 5. 재현

```
python -m pip install pytest
python -m pytest tests/test_stage1.py
python -m skillsplit.stage1.scan data/dev100 --out runs/stage1_v0_dev100.jsonl
cd data && python s1_rule_report.py      # runs_dev/s1_v0_rules.csv, runs_dev/s1_v0_samples.csv
```
