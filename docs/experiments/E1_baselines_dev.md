# E1. 기존 정적 탐지기 2종의 dev 기준선 (Cisco 정적 / SkillGate 규칙만)

실행일 2026-10-07. 담당 정적 탐지기(왕민). **dev(train+validation) 8,348개만 썼고 test는 보지 않았다.**

## 0. 한 줄 결론

- dev 전체에서 Cisco(정적)는 **악성 재현율 31.0%, 정상 오탐률 0.8%**, SkillGate(규칙만)는 **재현율 42.2%, 오탐률 25.3%**다. Macro-F1은 각각 0.447, 0.470.
- SkillGate의 규칙만 오탐률 25.3%는 논문 Table VI의 27.1%와 비슷하다. 재현율 42.2%는 논문 90%의 절반 이하다(데이터가 다름).
- 악성 6,658개 중 **3,052개(45.8%)는 두 도구 모두 놓친다.** 둘을 OR로 합쳐도 재현율 54.2%에 오탐률 25.6%다.
- SkillGate의 실제 동작 규칙은 **530개**(논문 수치와 일치)이고, 그중 dev에서 한 번이라도 걸린 것은 **217개**다. Sigma 유래 102개 중 걸린 것은 2개뿐이다.

## 1. 설정

| 항목 | 값 |
|---|---|
| 데이터 | MaliciousSkillBench `primary`, 공식 `source_disjoint.csv`의 train+validation = 8,348 (악성 6,658 / 정상 1,690). SKILL.md 본문만 |
| Cisco | `cisco-ai-skill-scanner==2.2.1`, `skill-scanner scan-all <dir> --format json`. 기본 설정 = 정적 분석기만, **LLM 끔, behavioral 끔**. 추가로 `--use-behavioral`(논문 설정)도 돌림. 판정: `is_safe == False` (HIGH/CRITICAL 기준과 결과 동일) |
| SkillGate | `awsm-research/skillgate@c1641c5` (2026-07-28). `create_classifier(use_llm=False)` = CLI `skillgate scan`의 기본값. 규칙에 하나라도 걸리면 MEDIUM으로 악성 처리 (논문 Table VI "규칙만") |
| 환경 | Windows 11, Python 3.12.10. 도구별 venv(`data/.venv-cisco`, `data/.venv-skillgate`) |
| 지표 | MaliciousSkillBench 논문과 같은 Macro-F1, 악성 재현율, 정상 오탐률 (R4 1(c)) |

## 2. 결과

| 도구 | Macro-F1 | 악성 재현율 | 정상 오탐률 | 스캔 실패 |
|---|---:|---:|---:|---:|
| Cisco 2.2.1 정적 | 0.447 | 0.310 (2,063/6,658) | 0.008 (14/1,690) | 0 |
| Cisco 2.2.1 정적 + behavioral | 0.448 | 0.312 (2,075/6,658) | 0.009 (15/1,690) | 0 |
| SkillGate 규칙만 | 0.470 | 0.422 (2,810/6,658) | 0.253 (428/1,690) | 0 (주) |
| OR (둘 중 하나) | | 0.542 | 0.256 | |
| AND (둘 다) | | 0.190 | 0.006 | |

(주) `ASB04_002434` 1개는 60초 안에 끝나지 않았다. sigma를 뺀 attack 규칙만으로 CRED014가 걸리는 것을 확인했고, 규칙 하나만 걸려도 악성이므로 전체 판정을 "악성"으로 채웠다(§3-3).

split별 Cisco 재현율: train 30.9%, validation 31.7% (차이 작음).

behavioral을 켜면 판정이 바뀐 샘플은 13개뿐이다(모두 안 걸림 → 걸림; 악성 12, 정상 1). 새로 걸린 규칙은 `MDBLOCK_PYTHON_EVAL_EXEC` 11, `MDBLOCK_PYTHON_SUBPROCESS` 2, `BEHAVIOR_BASH_TAINT_FLOW` 2로, SKILL.md 안 코드 블록을 분석한 결과다. behavioral은 주로 스크립트 파일을 분석하는데 이 데이터에는 SKILL.md만 있어서 효과가 작은 것으로 보인다. 아래 표와 OR/AND, 4칸 분해, 출처별 수치는 기본 설정 기준이다.

악성의 4칸 분해: Cisco만 796, SkillGate만 1,543, 둘 다 1,267, **둘 다 놓침 3,052**.

### 2.1 출처 유형(provenance)별

| provenance | 라벨 | n | Cisco | SkillGate |
|---|---|---:|---:|---:|
| synthetic | 악성 | 160 | 0.775 | 0.875 |
| wild | 악성 | 222 | 0.423 | 0.667 |
| injected | 악성 | 2,771 | 0.319 | 0.280 |
| mixed_unresolved | 악성 | 3,418 | 0.281 | 0.505 |
| test_fixture | 악성 | 86 | 0.012 | 0.221 |
| wild | 정상 | 1,490 | 0.007 | 0.232 |
| injected | 정상 | 153 | 0.020 | 0.516 |
| test_fixture | 정상 | 47 | 0.021 | 0.064 |

synthetic은 두 도구 모두 잘 잡고, injected는 둘 다 30% 안팎이다. source_id별 표는 `python score.py dev_labels.csv runs_dev` 출력에 있다.

### 2.2 SkillGate에서 자주 걸린 규칙

| 규칙 | severity | 내용 | 악성 (n=6,658) | 정상 (n=1,690) |
|---|---|---|---:|---:|
| CMD001 | MEDIUM | `\bcurl\s+` | 19.4% | 6.9% |
| ENC004 | MEDIUM | 긴 base64 토큰 | 8.5% | 5.6% |
| CRED014 | HIGH | 하드코딩된 API 키 형태 | 3.2% | 5.0% |
| RCE001 | CRITICAL | curl을 셸로 파이프 | 5.9% | (상위 10 밖) |

오탐된 정상 428개 중 221개(52%)는 **규칙 하나만** 걸렸다. LLM을 끄면 규칙 하나만 걸려도 악성 처리되므로, 넓은 규칙 하나가 곧 오탐이 된다. CRED014는 정상에서 더 자주 걸린다.

Cisco에서 악성에 자주 걸린 규칙(HIGH 이상): MANDATORY_AUTOMATIC_HELPER_EXECUTION 738, PIPELINE_TAINT_FLOW 486, CORRELATED_NETWORK_EXECUTION_FLOW 362, ACTIVE_DYNAMIC_EXECUTION 250. 단일 패턴보다 **결합 조건 규칙**이 상위에 있다.

## 3. 발견 사항

1. **SkillGate의 "530개"는 실제 로드되는 수다.** 저장소에는 attack 428 + sigma 105 = 533개가 있지만, sigma 3개(SIGMA002/048/096)는 정규식 컴파일에 실패하고 `try/except`로 조용히 빠진다. 533 − 3 = 530으로 논문 "428 + 102"와 일치한다(R1 §10의 미확인 항목 해결). `rules/*.yaml` 16개는 `load_custom_rules()`를 부르는 곳이 없어 기본 실행에서 로드되지 않는다.
2. **Sigma 유래 규칙은 사실상 동작하지 않는다.** 105개 중 86개가 이스케이프가 이중으로 들어가 있어(`\\-c` = 백슬래시 문자 + `-c`) 일반 텍스트에 걸리지 않는다. dev에서 걸린 sigma 규칙은 SIGMA003, SIGMA070 두 개뿐이고, 이중 이스케이프 86개는 0개 걸렸다. attack 428개 중에서는 215개가 한 번 이상 걸렸다.
3. **20MiB 한 줄 샘플에서 SkillGate가 멈춘다.** `ASB04_002434`(악성, SRC001)는 한 줄이 20,971,520자다. SkillGate sigma 규칙 `(?=.*a)(?=.*b).*`는 줄 길이의 제곱으로 느려져 끝나지 않는다(실제 배포라면 스캐너가 멈추는 약점). 래퍼에서 샘플당 60초 제한을 두어 일단 스캔 실패로 기록했다. 그다음 sigma를 뺀 attack 규칙 428개만 한 개씩 돌렸다(`AttackPatternMatcher(include_sigma=False)`, `scan(prefilter=True)`와 같은 필터, 규칙당 최대 3.3초). 그 결과 CRED014(HIGH)가 걸렸다. 규칙만 모드의 판정은 "하나라도 걸리면 악성"이고 sigma 규칙은 걸린 규칙을 더할 뿐이라, 전체 판정도 "악성"으로 확정된다. `runs_dev*/skillgate.json`의 이 샘플 항목에 `flag=1`, `rules=["CRED014"]`, `note`를 채웠다(원래 `error`는 남김). sigma 규칙이 이 파일에서 무엇을 더 걸었을지는 알 수 없다. Cisco는 같은 파일을 `SKILL_LOAD_REJECTED_LIMIT`(크기 초과, HIGH)로 걸었다. 내용이 아니라 크기 때문에 걸린 것이다.
4. **Windows 줄바꿈.** 텍스트 모드로 쓰면 `\n`이 `\r\n`이 된다. `make_dev.py`는 `newline=""`로 원문을 그대로 쓰고, 8,348개 모두 `skills.csv`와 바이트 단위로 일치함을 확인했다. dev100(CRLF로 쓰인 상태)과 dev 전체(LF)에서 같은 100개를 비교하면 두 도구 모두 판정·걸린 규칙 차이가 0건이었다. `sample.py`, `make_test.py`도 같은 방식으로 쓰고 있다.
5. **Windows Defender.** dev 파일을 쓰는 중 Defender가 `Trojan:AIAgent/ClawHavoc`, `Trojan:JS/ClawHavoc`, `Trojan:PowerShell/Openclaw.GVB` 등으로 38개 이상을 격리했다. `data/`를 예외 폴더로 등록한 뒤 다시 만들었고, 이후 탐지는 없었다. 폴더 수만 세면 놓친다(폴더는 남고 SKILL.md만 사라짐). 파일 수와 해시로 확인해야 한다.
6. **규칙만 모드에서는 SkillGate의 예외 규칙(SAFE_PATTERNS)이 적용되지 않는다.** LLM을 끄면 판정이 `scan(prefilter=True)` 결과로 정해진다(`hybrid.py:97`). prefilter 모드는 allowlist(SAFE_PATTERNS 132개)와 문서 문맥 예외를 끈다(`attack_patterns.py:1931`, `:1951`). 코드상으로는 정상 문서용 예외가 판정에 쓰이지 않는다는 뜻이다. 이것이 오탐률 25.3%의 한 원인일 수 있다(예외를 켠 실험은 하지 않음).

## 4. 비교할 때 주의

- **Cisco 설정.** MaliciousSkillBench 논문의 Cisco는 "Cisco-local-behavioral"(behavioral 켬, HIGH/CRITICAL)이다. dev에서는 두 설정을 모두 돌렸고 차이가 재현율 +0.2%p, 오탐률 +0.1%p로 작다. 그래도 test 기준선과 비교할 때는 같은 설정끼리 놓는다. 논문 비교용은 behavioral 켬이다. behavioral 분석기는 코드를 실행하지 않는 정적 데이터 흐름 분석이다(`behavioral_analyzer.py` 머리말 "without execution").
- **dev 숫자는 test 숫자를 예측하지 않는다.** 공식 분할은 test를 dev에 없는 출처로 구성한다(출처 분리). 그래서 dev 재현율이 test 재현율을 예측하지 않는다(논문 Cisco test 재현율 2.5%).
- **SkillGate 비교 기준은 논문 Table VI 규칙만**(재현율 90%, 오탐 27.1%, SkillsBench-1650)이다. 데이터가 다르므로 차이의 원인을 이 실험만으로 말할 수 없다.

## 5. 우리 정적 탐지기 설계에 주는 것

- "curl이 있다" 같은 **단일 명령 규칙은 정상과 구분하지 못한다**(CMD001 악성 19.4% 대 정상 6.9%). 규칙은 "받아서 실행", "읽어서 보냄"처럼 **행위의 결합**으로 쓴다. Cisco 상위 규칙도 결합 조건이다.
- 키 문자열 형태 규칙(CRED014)은 정상에서 더 자주 걸리고, 벤치마크 공개 텍스트는 실제 키를 `[REDACTED_AWS_ACCESS_KEY]`로 가린다. 자격증명은 **경로 접근 행위**로 잡는다.
- **긴 줄·큰 파일 처리**를 탐지기 입력 단계에 넣는다(자르기 또는 크기 자체를 신호로). 정규식에 `.*` 룩어헤드를 쓰지 않는다.
- 다음 분석 대상: 두 도구가 모두 놓친 악성 3,052개, 특히 injected(재현율 30% 안팎).

## 6. 재현

```
cd data
python make_dev.py                                    # dev_skills/ 8,348개 + dev_labels.csv
python -m venv .venv-cisco && .venv-cisco/Scripts/python -m pip install cisco-ai-skill-scanner==2.2.1
python get_rules.py                                   # rules_upstream/skillgate (고정 커밋) + rules_all.csv
python -m venv .venv-skillgate && .venv-skillgate/Scripts/python -m pip install ./rules_upstream/skillgate
.venv-cisco/Scripts/skill-scanner scan-all dev_skills --format json --output runs_dev/cisco.json   # 약 12분
.venv-cisco/Scripts/skill-scanner scan-all dev_skills --use-behavioral --format json --output runs_dev_behav/cisco.json   # 약 12분
cp runs_dev/skillgate.json runs_dev_behav/ && python score.py dev_labels.csv runs_dev_behav
.venv-skillgate/Scripts/python run_skillgate.py dev_skills runs_dev/skillgate.json               # 약 35분
.venv-skillgate/Scripts/python sg_attack_only.py dev_skills/ASB04_002434/SKILL.md > runs_dev/sg_attack_only_ASB04_002434.log
# ↑ 60초 초과 샘플을 attack 규칙만으로 확인, 결과를 skillgate.json에 수동 기입(§3-3)
python score.py dev_labels.csv runs_dev               # 결과표 + runs_dev/scores.csv(샘플별)
```

샘플별 결과(`runs_dev/scores.csv`: 정답, provenance, source_id, 도구별 판정, 걸린 규칙)는 git에 넣지 않는다. 필요하면 위 명령으로 다시 만든다.
