# E6. 정적 탐지기 v1 dev 결과 (동결 후보)

실행일 2026-11-04. 담당 정적 탐지기(왕민). 코드 커밋 `31333de`(규칙 17개). dev만 사용, test는 보지 않았다. v0는 [E5](E5_stage1_v0.md), 설계는 [stage1 README](../../skillsplit/stage1/README.md).

## 0. 한 줄 결론

- **dev는 규칙 설계에 쓴 데이터다.** 글 규칙은 dev에서 기존 도구가 놓친 사례(E2~E4)를 보고 만들었고, v1 조정도 dev 정상 오탐을 보고 했다. 아래 수치는 모두 v1에 유리하다. 공정한 비교는 5주차 test에서 한다.
- **주 지표는 재현율과 오탐률이다.** 정적은 안 걸리면 0점이라, 아무것도 못 잡아도 PR-AUC가 악성 비율만큼 나온다(dev 전체 0.798, dev100 0.500). PR-AUC는 같은 데이터에서 다른 탐지기와 비교할 때만 쓴다.
- dev 전체(8,348): **재현율 0.549(v0와 같음), 정상 오탐률 0.008(13/1,690, v0 21개)**. PR-AUC 0.907.
- **출처 쏠림을 빼면 재현율은 0.160이다.** 최다 출처 비중이 90% 이상인 규칙 9개를 빼고 잰 값이다. v0 재현율의 대부분은 SRC010·SRC001의 문장 틀에 맞춘 규칙에서 나온다(§2, §3).
- dev100: 재현율 0.640, 오탐률 0.000(0/50). 점수는 v0와 100개 모두 같다.
- v0에서 바꾼 것: RUN_DIRECTIVE를 RUN_CMD·RUN_INIT로 나눔(정규식 그대로), CRED_PATH에 자기 키를 쓰는 줄 예외, 채택 기준 2에 최다 출처 비중 상한. AST(v1 계획)와 SkillGate 규칙 추가는 재 보고 하지 않았다(§5, §6).

## 1. 규칙별 (dev 전체)

열 뜻은 E5 §1과 같다. status는 4주차 기준 2(출처 2개 이상 **그리고** 최다 출처 비중 < 90%)로 매겼다.

| rule | 심각도 | 악성 적중 | 정상 적중 | ben_rate | n_sources | 최다 출처 | new_vs_baselines | status |
|---|---|---:|---:|---:|---:|---|---:|---|
| RUN_CMD | HIGH | 1,832 | 0 | 0.0000 | 2 | SRC010 99% | 890 | 출처 편향 |
| RUN_INIT | HIGH | 684 | 0 | 0.0000 | 2 | SRC001 99% | 281 | 출처 편향 |
| PROMPT_LEAK | HIGH | 102 | 2 | 0.0012 | 3 | SRC001 90% | 44 | 출처 편향 |
| OVERRIDE | HIGH | 370 | 0 | 0.0000 | 2 | SRC001 52% | 92 | 채택 |
| LURE | HIGH | 164 | 1 | 0.0006 | 2 | SRC001 58% | 26 | 채택 |
| HOMOGLYPH | HIGH | 63 | 2 | 0.0012 | 2 | SRC001 92% | 38 | 출처 편향 |
| RECON_DUMP | MEDIUM | 9 | 0 | 0.0000 | 1 | SRC001 89% | 6 | 출처 편향 |
| HIDDEN_DIRECTIVE | MEDIUM | 137 | 1 | 0.0006 | 2 | SRC001 53% | 56 | 채택 |
| PERSONA_LOCK | MEDIUM | 3 | 0 | 0.0000 | 1 | SRC001 100% | 3 | 출처 편향 |
| CONCEAL (결합 전용) | MEDIUM | 644 | 0 | 0.0000 | 1 | SRC010 100% | 132 | 출처 편향 |
| DESC_BYPASS (결합 전용) | LOW | 31 | 1 | 0.0006 | 2 | SRC010 71% | 14 | 채택 |
| PIPE_TO_SHELL | CRITICAL | 336 | 1 | 0.0006 | 3 | SRC001 62% | 0 | 채택 |
| DECODE_EXEC | CRITICAL | 79 | 0 | 0.0000 | 2 | SRC001 58% | 0 | 채택 |
| REMOTE_EXEC | CRITICAL | 14 | 0 | 0.0000 | 1 | SRC001 100% | 0 | 출처 편향 |
| CRED_PATH | HIGH | 50 | 0 | 0.0000 | 2 | SRC001 90% | 0 | 출처 편향 |
| EXFIL_SEND | HIGH | 23 | 0 | 0.0000 | 2 | SRC001 78% | 0 | 채택 |
| PERSISTENCE | HIGH | 56 | 6 | 0.0036 | 2 | SRC001 80% | 0 | 채택 |

출처 편향 규칙도 점수에는 남긴다. 9개 합쳐 정상 적중이 4개뿐이라 오탐률 비용이 거의 없다. 대신 재현율을 포함·제외 두 가지로 보고한다(§2).

## 2. 전체와 출처별

| 조건 | 재현율 | 오탐률 | PR-AUC (전부 0점이면) |
|---|---:|---:|---:|
| dev 전체, 규칙 17개 | 0.549 | 0.008 (13/1,690) | 0.907 (0.798) |
| dev 전체, 출처 편향 9개 제외 | 0.160 | 0.005 (9/1,690) | 0.829 (0.798) |
| dev100 | 0.640 | 0.000 (0/50) | 0.820 (0.500) |

| 출처 | 악성 n | 재현율 | 출처 편향 제외 |
|---|---:|---:|---:|
| SRC001 | 3,418 | 0.408 | 0.171 |
| SRC002 | 153 | 0.569 | 0.569 |
| SRC004 | 33 | 0.121 | 0.121 |
| SRC005 | 30 | 0.100 | 0.100 |
| SRC006 | 86 | 0.116 | 0.035 |
| SRC008 | 1 | 1.000 | 0.000 |
| SRC010 | 2,783 | 0.771 | 0.138 |
| SRC013 | 154 | 0.032 | 0.000 |

Cisco(기본)와 네 칸(악성 6,658)은 v0와 같다: 정적만 2,024, Cisco만 434, 둘 다 1,629, 둘 다 놓침 2,571.

가중치를 모두 0.7로 같게 하면 PR-AUC는 0.9072 → 0.9070이다. 걸린 샘플 중 정상이 13개뿐이라 걸린 샘플끼리의 순서가 거의 영향이 없다(README §3.1).

## 3. RUN_DIRECTIVE 나누기 (PR #4 리뷰 4번)

v0 RUN_DIRECTIVE의 정규식은 갈래 5개를 `|`로 이은 것이다. 갈래별로 걸린 악성의 출처를 세어 보니 두 묶음으로 깔끔하게 나뉘었다.

| 새 이름 | 갈래 | 원래 신호 | 악성 적중 | 최다 출처 | new_vs_baselines |
|---|---|---|---:|---|---:|
| RUN_CMD | "must/first/required…" + `` `python x` `` (앞뒤 두 갈래) | E2 run_directive | 1,832 | SRC010 99% | 890 |
| RUN_INIT | "initialization script/step" (세 갈래) | E3 init_directive | 684 | SRC001 99% | 281 |

- E5에서 "SRC010 틀 문장과 일반 형태로 나눈다"고 했지만, **일반 형태는 따로 없었다.** 두 묶음 모두 각각 한 출처의 틀에 맞춰져 있다. E5의 "새로 잡은 1,170개"는 RUN_CMD 890 + RUN_INIT 281(1개 겹침)이다.
- 두 규칙 모두 v0 기준 2(출처 2개, 각 3건 이상)는 통과한다. 다른 출처 적중이 RUN_CMD 19개(SRC001 17, SRC013 2), RUN_INIT 5개(SRC006 4, SRC008 1)뿐인데도 그렇다. 그래서 기준 2에 **최다 출처 비중 < 90%**를 더했다. 이 상한에 새로 걸리는 규칙은 RUN_CMD, RUN_INIT, PROMPT_LEAK(90%), HOMOGLYPH(92%), CRED_PATH(90%)다.
- 정규식은 바꾸지 않았다. 점수가 달라지는 것은 두 묶음에 함께 걸리는 6개(0.7 → 0.91)뿐이고, 걸림 여부는 바뀌지 않는다.

## 4. 정상 오탐 21개 (v0)

dev 정상 1,690개는 모두 SRC010이다. 오탐 21개를 걸린 줄의 형태로 묶으면 10가지 정도다.

| 규칙 | 개수 | 걸린 형태 | 처리 |
|---|---:|---|---|
| CRED_PATH | 8 | `ssh-add ~/.ssh/id_ed25519` (8개 모두 같은 줄) | **예외 추가**: 줄이 `ssh-add`·`ssh-keygen`·`ssh -i`로 시작하면 셈하지 않음. 정상 −8, 악성 손실 0 |
| PERSISTENCE | 5 | `echo 'export KEY=…' >> ~/.zshrc` (환경변수 등록 안내) | 그대로. `echo 'export/alias/source…' >>` 예외를 두면 정상 −5지만 악성 3개(그 규칙만 걸린 것)를 잃음 |
| PERSISTENCE | 1 | `systemctl --user enable` (서비스 등록 안내) | 그대로 |
| PROMPT_LEAK | 2 | "share the context window with … system prompt" | 그대로 |
| HOMOGLYPH | 2 | 그리스 문자 단위·기호(`μm`, `ΔC`) | 그대로. 악성 적중 63개 중 31개가 그리스 문자만 섞인 경우라 그리스 문자를 빼면 손실이 큼 |
| LURE | 1 | "paste the user's raw request into shell" | 그대로 |
| HIDDEN_DIRECTIVE | 1 | HTML 주석 안 "… sections are never" | 그대로 |
| PIPE_TO_SHELL | 1 | 공식 설치 스크립트 `curl … \| sh` | 그대로 |

PERSISTENCE 6개 중 1개에는 DESC_BYPASS도 함께 걸렸다(결합 전용이라 PERSISTENCE가 짝). 처리 후 오탐은 13개(0.8%)다.

## 5. 소수 출처 (SRC002·004·005·006·013)

| 출처 | 악성 n | v1 | Cisco | SkillGate | 셋 다 놓침 | 많은 공격 유형(메타데이터) |
|---|---:|---:|---:|---:|---:|---|
| SRC002 | 153 | 87 | 89 | 118 | 34 | 자격증명 + 코드 실행 + 지시 조작 |
| SRC004 | 33 | 4 | 2 | 15 | 18 | 코드 실행, 난독화 |
| SRC005 | 30 | 3 | 1 | 13 | 16 | (유형 표시 없음) |
| SRC006 | 86 | 10 | 1 | 19 | 64 | 유출, 출력 조작, 지시 조작 |
| SRC013 | 154 | 5 | 7 | 30 | 119 | 출력 조작, 지시 조작, 코드 실행 |

- SkillGate가 소수 출처에서 더 잡는 몫은 대부분 `wget`·`mv`·`zip`·`curl` 같은 명령 하나짜리 규칙이다(CMD001 `curl`은 dev 정상 6.9%). README §2.3에서 "정상과 구분하지 못함"으로 뺀 종류다.
- 정상 적중률 0.5% 이하이면서 소수 출처에서 v0가 놓친 악성을 3개 넘게 잡는 규칙 3개를 dev 전체 코드 블록에서 재 봤다. **옮기지 않았다.**

| SkillGate 규칙 | 내용 | 악성 | 정상 | 최다 출처 | v1이 놓친 악성 중 새로 | 옮기지 않은 이유 |
|---|---|---:|---:|---|---:|---|
| CMD033 | `cat`으로 민감 경로 읽기 | 91 | 7 | SRC001 71% | 25 | 새로 잡는 25개 중 17개가 `cat ~/.설정파일`. 정상 오탐 7개와 같은 형태(`~/.config/…/client_id` 등) |
| RCE009 | `$(cat /경로)` | 32 | 4 | SRC001 53% | 19 | 새로 잡는 19개 중 14개가 `$(cat /tmp/…)`. 정상 오탐과 같은 형태 |
| DISC101 | `env` 출력 덤프 | 96 | 1 | SRC001 96% | 49 | 출처 편향이고, 코드 펜스 첫 줄 ```` ```env ````를 잘못 잡음 |

- dev 정상이 SRC010 한 출처뿐이라, 위 오탐률은 다른 출처의 정상에서 더 높을 수 있다. 숫자로는 §4 기준 1·2를 통과해도, 새로 잡는 몫이 정상과 같은 형태라 일반화 근거가 없다고 봤다.
- SRC006·SRC013에서 셋 다 놓친 악성은 출력 조작·지시 조작처럼 글의 뜻을 봐야 하는 유형이 많다. 정해 둔 단어 목록으로 잡는 정적 규칙의 범위 밖이고, 2단계 몫으로 둔다.

## 6. v1 AST를 만들지 않은 이유

계획(README §6)은 DECODE_EXEC·PIPE_TO_SHELL에 AST를 붙여 줄을 넘는 경우를 잡는 것이었다. 만들기 전에, 코드 블록 하나 안에서 줄을 넘는 결합을 정규식으로 넉넉하게 세어 AST로 더 잡을 수 있는 몫의 상한을 쟀다.

| 결합 (코드 블록 하나 안, 줄 무관) | 악성 | 정상 | v1이 놓친 악성 |
|---|---:|---:|---:|
| base64 디코드 + exec/eval/`\| sh`/subprocess/os.system | 42 | 0 | 6 (모두 SRC001) |
| 내려받기(curl/wget/requests.get 등) + exec/eval | 9 | 0 | 0 |
| 줄 이음 `\`로 넘어간 `curl … \| sh` | 0 | 0 | 0 |

상한이 6개(재현율 +0.1%p)라 tree-sitter-bash 의존성을 더할 만큼의 이득이 없다. 코드 블록 규칙은 v0에서도 기존 도구와 겹치는 샘플만 잡았다(new_vs_baselines 0).

## 7. 동결 규칙 목록

규칙 17개(`31333de`): RUN_CMD, RUN_INIT, PROMPT_LEAK, OVERRIDE, LURE, HOMOGLYPH, RECON_DUMP, HIDDEN_DIRECTIVE, PERSONA_LOCK, CONCEAL(결합 전용), DESC_BYPASS(결합 전용), PIPE_TO_SHELL, DECODE_EXEC, REMOTE_EXEC, CRED_PATH(예외 있음), EXFIL_SEND, PERSISTENCE. 가중치 CRITICAL 0.9, HIGH 0.7, MEDIUM 0.4, LOW 0.2. 5주차 test 평가는 이 목록으로 하고, test 결과를 보고 규칙을 바꾸지 않는다.

"스크립트에만 공격"(E4 약 20%)의 평가 처리는 윤세훈 님이 정해 공지하기로 했다(PR #4 리뷰). 탐지기 쪽은 바꾸지 않는다.

## 8. 재현

```
python -m pytest tests/test_stage1.py
python -m skillsplit.stage1.scan data/dev100 --out runs/stage1_v1_dev100.jsonl
python -m skillsplit.stage1.scan data/dev_skills --out runs/stage1_v1_dev.jsonl
cd data && python s1_rule_report.py      # runs_dev/s1_v1_rules.csv, runs_dev/s1_v1_samples.csv
```

§3·§4·§5·§6의 갈래별·형태별 집계는 일회성 확인이라 스크립트로 남기지 않았다(원문은 출력하지 않고 개수와 정상 샘플의 걸린 줄만 봄).
