# 기준선 도구 (baselines)

우리 탐지기의 숫자 옆에 놓을 공개 스캐너 넷을 같은 `predictions.csv` 형식으로 돌리는 방법을 적는다. 실행기는 `baselines/run_baseline.py` 하나다. 이 문서의 수치는 전부 2026-09-25에 이 저장소에서 직접 돌린 결과다. 논문 수치를 옮긴 곳은 출처를 붙였다.

## 1. 왜 기준선이 필요한가

"우리 2단계 탐지기가 PR-AUC 0.8을 냈다"는 문장은 혼자서는 아무 뜻이 없다. 같은 데이터, 같은 입력 조건에서 이미 있는 도구가 얼마를 내는지 옆에 있어야 우리 숫자가 좋은지 나쁜지 읽힌다. 기준선은 세 가지 일을 한다.

- **비교 대상**: 우리 1단계(정적 규칙)와 2단계(LLM 판정)를 Cisco skill-scanner, NVIDIA SkillSpector, SkillFortify, SkillGate 옆에 놓는다. 넷 다 무료로 로컬에서 돌고, 앞의 셋은 MaliciousSkillBench 논문이 이미 같은 벤치마크에서 돌린 도구다.
- **파이프라인 검증**: 기준선이 `predictions.csv`를 내고 `eval/evaluate.py`가 그것을 읽으면, 우리 탐지기가 나오기 전에 평가 코드가 먼저 검증된다.
- **재현 확인**: MaliciousSkillBench 논문의 스캐너 수치(Source-Disjoint test)를 우리 환경에서 다시 내 보면, 우리 환경과 논문 환경의 차이가 얼마인지 알 수 있다. 그 차이보다 작은 우리 개선은 개선이 아니다.

기준선은 우리가 만든 것이 아니므로 **튜닝하지 않는다.** 각 도구가 문서에 적어 둔 판정(gate)을 그대로 쓴다.

## 2. 도구 넷

| | Cisco skill-scanner | NVIDIA SkillSpector | SkillFortify | SkillGate (awsm-research) |
|---|---|---|---|---|
| 버전 | 2.1.0 (PyPI wheel) | 2.12.0, git `c7958a3` | 0.6.0 (PyPI) | 0.1.0, git `c1641c5` |
| 방식 | YARA 정적 규칙 + bytecode + pipeline + correlation + `--use-behavioral`(AST 데이터흐름). 전부 로컬 | 정적 규칙(regex/YARA/AST) + 선택적 LLM. `--no-llm`으로 정적만 | SKILL.md 패턴 매칭(attack_class 5종: data_exfiltration, privilege_escalation, prompt_injection, dependency_confusion, typosquatting / attack_type A1~A13). 완전 오프라인 | regex prefilter(530 패턴, 논문 기준. 저장소 `c1641c5`의 rule id는 537개) → 선택적 LLM judge. LLM 없이는 prefilter만 |
| 설치 | `pip install cisco-ai-skill-scanner==2.1.0` | `pip install "git+https://github.com/NVIDIA/SkillSpector.git@c7958a3268d9498644b22edb75d0f051bbc8cbfc"` (PyPI에 없음) | `pip install skillfortify==0.6.0` | `pip install "git+https://github.com/awsm-research/skillgate.git@c1641c5d5664634296977ff7491f4cff469acfb7"` (PyPI `skillgate`는 다른 회사 제품) |
| 실행 (run_baseline.py가 호출) | `skill-scanner scan-all <root> --use-behavioral --format json` | `skillspector scan <root> --recursive --no-llm --format json` | `skillfortify scan <root> --format json` (`<root>/skills/<name>/SKILL.md` 레이아웃) | CLI에 JSON 없음. venv python으로 `create_classifier(use_llm=False).classify(text, ScanContext(source_path=...))` 스니펫 실행 |
| `score` (0~1) | `max_severity` 매핑: NONE/INFO 0, LOW .25, MEDIUM .5, HIGH .75, CRITICAL 1 | `risk_assessment.score / 100` | `max_severity` 매핑(위와 같음, null → 0) | prefilter hit 1개 이상 → 0.5 (도구가 고정으로 내는 MEDIUM), 없으면 0 |
| `verdict` (도구 원래 판정) | `is_safe` → `SAFE` / `UNSAFE` | `recommendation`: `SAFE` / `CAUTION` / `DO_NOT_INSTALL` | `is_safe` → `SAFE` / `UNSAFE` | `severity` 이름(`MEDIUM`) 또는 `SAFE` |
| `evidence` | 심각도 순 상위 5개 `rule_id` (INFO 제외) | 상위 5개 issue `id` (SC2, PE3 ...) | `attack_class:attack_type` 상위 5개 | 매치된 rule id 상위 5개 (CMD039, OBFUS025 ...) |
| 라이선스 | Apache-2.0 | Apache-2.0 | **Elastic-2.0** (OSI 오픈소스 아님. 로컬 연구 실행은 가능, 호스팅 서비스 제공 불가) | MIT |
| 함정 | (1) `--fail-on-findings` 없이는 exit code가 항상 0이므로 JSON의 `is_safe`를 쓴다. (2) JSON의 `skill_name`은 frontmatter `name`이지 디렉터리명이 아니다. `skill_path`로 조인한다. (3) `file_path`에 `/`와 `\\`가 섞인다. (4) `MANIFEST_MISSING_LICENSE`(INFO)는 거의 항상 뜬다. 0점 처리. (5) 호출당 약 10초 고정비용(magika 모델 로드). 배치로 돌린다. (6) MaliciousSkillBench 논문은 commit 48f5934 + yara-x 1.4.0 환경이라 2.1.0과 같지 않다 | (1) SC4 규칙이 api.osv.dev를 조회한다. 오프라인이면 폴백. (2) 위험도 50 초과면 exit 1이 정상이다. exit code를 무시하고 stdout JSON을 읽는다. (3) **`CAUTION`은 점수 0이어도 뜬다.** 분석이 불완전하면(`analysis_completeness.is_complete=false` 등) `SAFE`를 `CAUTION`으로 올린다(`nodes/report.py`). CAUTION+ 2차 게이트는 `recommendation`이 아니라 `score > 20`으로 계산한다. (4) `metadata.llm_available: true`는 키 없이도 true다. `llm_requested: false`만 본다. (5) **`--recursive`는 호출당 32개까지만 스캔한다** (`cli.py`의 `_MULTI_SKILL_MAX_SKILLS = 32`, 환경변수 없음). 33번째부터는 `{"omitted": true, "omitted_count": N, "reason": "aggregate_scan_limit"}` 한 항목으로 뭉뚱그려진다. run_baseline.py는 배치를 32로 자른다. 32건 배치 결과는 단일 `scan` 결과와 같았다(3건 대조: 점수, issue 목록, completeness 모두 동일. 세션 내 관찰이며 raw stdout은 보존되지 않았다). (6) 넷 중 가장 느리다(건당 약 1초) | (1) 맨 디렉터리(`<dir>/SKILL.md`)는 "No skills found". 반드시 `<root>/skills/<name>/SKILL.md`. (2) **scripts를 읽지 않는다.** 아래 스모크에서 full-package와 SKILL.md-only 결과가 20건 전부 같았다. (3) JSON에 경로가 없고 `skill_name`은 frontmatter `name`이 있으면 그것을 쓴다. 배치로 돌리면 어느 결과가 어느 스킬인지 알 수 없어 **run_baseline.py는 1건씩 호출**한다(`--batch` 무시). (4) finding 있으면 exit 1, 스킬 못 찾으면 exit 2 | (1) LLM 없이는 판정이 사실상 이진이다(hit → MEDIUM 고정). (2) `source_path`를 주면 스킬 루트를 찾아 패키지 전체를 합쳐 판정한다. 그래서 full-package와 SKILL.md-only 결과가 다르다. (3) `pip install skillgate`는 다른 제품(1.2.3)이 깔린다. (4) 데몬/Unix socket 기능은 Windows에서 미검증 |

공통 규칙:

- 실패는 절대 정상으로 만들지 않는다. 파일 없음, 도구 크래시, JSON 파싱 실패, 결과 누락은 모두 `score=0.0` + `error=ABSTAIN_ERROR:<사유>`로 적는다. 평가에서는 이 행을 분모에서 빼고 coverage를 따로 보고한다.
- `runs/baseline_<tool>_<날짜>.meta.json`에 도구 버전(`pip show`), 명령줄(skillgate는 `command_template`에 스니펫 대신 `...`이 들어가고 `argv`만 보존된다), 배치별 소요 시간, 실행 환경을 남긴다. `runs/baseline_<tool>_<날짜>.raw/`에 도구의 원본 stdout/stderr를 배치별로 남긴다.
- 매니페스트의 `path`가 빈 행은 `ABSTAIN_ERROR:no_path`로 적는다.

실행 예:

```
python baselines/run_baseline.py --tool cisco --manifest data/manifest.csv \
    --exe <venv_cisco>/Scripts/skill-scanner.exe --skill-md-only --batch 200
python baselines/run_baseline.py --tool skillgate --manifest data/manifest.csv \
    --exe <venv_sg>/Scripts/python.exe --skill-md-only
```

`--exe`를 생략하면 PATH의 `skill-scanner` / `skillspector` / `skillfortify` / `python`을 쓴다. 도구마다 venv를 따로 두는 것을 권한다(SkillSpector 의존성이 무겁다).

## 3. MaliciousSkillBench는 스캐너를 어떻게 돌렸나, 우리는 무엇을 맞추나

MaliciousSkillBench(arXiv:2608.19901) 저장소의 `scanner_eval/`에는 결과 CSV와 README만 있고 래퍼 코드는 없다. 규칙은 논문 부록 J에만 있다. 원문 네 문장이 우리가 맞출 조건이다.

**입력은 SKILL.md 사본 하나다** (J.1):

> All three scanners are evaluated on the same primary static artifact used by the learned text baselines: an isolated SKILL.md copy of each frozen benchmark unit. This is therefore a common primary-artifact comparison whose scope is limited to static Skill text and excludes full-package/runtime behavior.

**게이트는 사전 등록한다** (J.1):

> Cisco-local-behavioral uses the native HIGH/CRITICAL safety gate; SkillFortify-offline uses an explicit MEDIUM+ rule over saved maximum severity; and SkillSpector-static disables LLM analysis and treats its native block/DO NOT INSTALL state as positive.

**실패는 세 번째 상태다** (J.1):

> Technical failures remain a third state, ABSTAIN ERROR, and are never silently converted to benign predictions. Primary binary metrics therefore use successful scans while reporting coverage separately.

**한 번 스캔하고 분할 매니페스트에 조인한다** (J.2):

> Because the scanners are fixed external tools, each benchmark unit is scanned once and predictions are joined to the existing frozen protocol test manifests; scanners are not retrained for any protocol.

임계값 튜닝 금지 (G.4): "We do not calibrate probabilities or tune a decision threshold on the validation partition for the primary comparisons."

우리가 맞추는 조건 네 가지:

| 조건 | 우리 구현 |
|---|---|
| 단일 SKILL.md 사본 | `--skill-md-only`. MaliciousSkillBench는 benign 2,235건에 패키지가 없어(HF `primary`의 `skill_text`뿐) full-package로 돌리면 malicious만 스크립트를 갖는 비대칭이 생긴다. MaliciousSkillBench 비교 표는 반드시 이 조건으로 만든다 |
| 사전 등록 게이트 | `predictions.csv`의 `verdict`에서 그대로 계산한다. Cisco `verdict == UNSAFE` (= `is_safe == false`, HIGH/CRITICAL), SkillFortify `score >= 0.5` (= MEDIUM+), SkillSpector `verdict == DO_NOT_INSTALL` (= score > 50). 2차 게이트(논문 Table 45): Cisco MEDIUM+ `score >= 0.5`, SkillSpector CAUTION+ `score > 0.20`, SkillFortify HIGH+ `score >= 0.75` |
| ABSTAIN_ERROR | `error` 열. 평가 시 분모에서 제외, coverage 별도 보고 |
| Source-Disjoint test로 조인 | 9,740건 전체를 한 번 스캔한 뒤 `metadata/splits/source_disjoint.csv`의 `split == "test"` 1,384건(839 malicious / 545 benign)과 `benchmark_id`(= 우리 `skill_id`의 `asb:` 뒤. `msb:`는 MalSkillBench다)로 조인. 지표는 논문 형식(Macro-F1, malicious recall, benign FPR)을 `evaluation/metrics.py`의 `detection_metrics`와 같은 정의로 낸다 |

논문의 Source-Disjoint 수치(`scanner_eval/source_disjoint_results.csv` 원문):

```
method,protocol,macro_f1,malicious_recall,benign_fpr
Cisco-local-behavioral,source_disjoint,0.308,0.025,0.011
SkillFortify-offline,source_disjoint,0.349,0.253,0.499
SkillSpector-static,source_disjoint,0.281,0.000,0.0055
Word-SVM,source_disjoint,0.665,0.956,0.624
```

이 수치는 **재현 대상이 아니라 참고값**이다. 논문의 Cisco는 commit 48f5934 + yara-x 1.4.0 환경이고 우리는 2.1.0 wheel이다. Cisco README("Current modernization evidence" 절)는 Source-Disjoint 결과를 "TP=65, FP=42, TN=503, and FN=774, for 60.75% precision, 7.75% recall, 13.74% F1, and 7.71% FPR"로 따로 보고한다. 다만 이 절은 스캐너 버전을 명시하지 않고("the current scanner"), 입력이 논문의 SKILL.md 사본이 아니라 "MaliciousSkillBench packages"이므로 논문 수치와 같은 조건이 아니다. 보고서에는 우리가 돌린 버전과 우리 수치를 적고 논문 수치는 옆에 병기한다.

## 4. 왜 Snyk agent-scan은 제외하나

Snyk agent-scan은 MalSkillBench 논문에 기준선으로 등장하지만 우리는 돌리지 않는다. 이유는 README(https://github.com/snyk/agent-scan) 원문에 있다.

> Agent Scan validates discovered components with local checks and the Agent Scan API. It sends the component information needed for analysis, including agent application details, MCP server configurations and signatures, tool names and descriptions, and skill content. Secrets in configuration values and text are redacted before transmission.

> If you want to include Agent Scan results in your own project or registry, please reach out. There are designated APIs for this purpose. Using the standard Agent Scan API for large scale scanning is considered abuse and will result in your account being blocked.

즉 (1) 오프라인 실행이 없고 `SNYK_TOKEN` 계정이 필요하며, (2) 스킬 본문이 Snyk 서버로 전송되고, (3) 9,740건 대량 스캔은 약관상 abuse다. 벤치마크의 malicious 텍스트를 제3자 서버로 보내는 것은 MaliciousSkillBench `RESPONSIBLE_USE.md`("Use the data in isolated, non-production analysis environments")와도 맞지 않는다. 관련 도구로 언급만 한다.

## 5. 스모크 결과 (SkillTrustBench 20건)

조건: SkillTrustBench `benchmark_full_v1.0`에서 `ground_truth.json`의 `judgment == "malicious"` 앞 10건과 `"normal"` 앞 10건. 전부 `origin_group = synthetic`(injected / safe_pool). Windows 11, CPython 3.13, 도구별 venv. 네 도구를 순서대로 한 번씩 돌렸다(동시 실행 없음). 매니페스트와 결과 파일은 `runs/smoke_stb20/`에 있다. 스모크 매니페스트는 `docs/data-format.md` 계약의 축소판이다(`files_expected`, `intact` 열이 없고 `smoke_stb200`은 `origin_group`, `has_script`가 공란). 20건이므로 성능 결론은 내지 않는다. 파이프라인이 도는지, 조건에 따라 무엇이 달라지는지만 본다.

게이트 = 각 도구의 1차 게이트(§3). 재현율 분모 10(malicious), FPR 분모 10(normal).

| 도구 | 조건 | 벽시계(초) | malicious score 평균 / 최소 / 최대 | normal score 평균 / 최소 / 최대 | 게이트 재현율 | 게이트 FPR | malicious verdict | normal verdict |
|---|---|---|---|---|---|---|---|---|
| cisco | full-package | 25.3 | 0.95 / 0.75 / 1.00 | 0.42 / 0.00 / 1.00 | 10/10 | 3/10 | UNSAFE 10 | SAFE 7, UNSAFE 3 |
| cisco | SKILL.md-only | 11.5 | 0.35 / 0.00 / 0.75 | 0.00 / 0.00 / 0.00 | 4/10 | 0/10 | UNSAFE 4, SAFE 6 | SAFE 10 |
| skillspector | full-package | 81.6 | 0.72 / 0.28 / 1.00 | 0.31 / 0.00 / 0.89 | 6/10 | 3/10 | DO_NOT_INSTALL 6, CAUTION 4 | CAUTION 6, DO_NOT_INSTALL 3, SAFE 1 |
| skillspector | SKILL.md-only | 25.6 | 0.04 / 0.00 / 0.16 | 0.07 / 0.00 / 0.42 | 0/10 | 0/10 | CAUTION 10 | CAUTION 10 |
| skillfortify | full-package | 6.6 | 0.30 / 0.00 / 0.75 | 0.30 / 0.00 / 0.75 | 4/10 | 4/10 | SAFE 6, UNSAFE 4 | UNSAFE 4, SAFE 6 |
| skillfortify | SKILL.md-only | 6.2 | 0.30 / 0.00 / 0.75 | 0.30 / 0.00 / 0.75 | 4/10 | 4/10 | SAFE 6, UNSAFE 4 | UNSAFE 4, SAFE 6 |
| skillgate | full-package | 14.6 | 0.35 / 0.00 / 0.50 | 0.30 / 0.00 / 0.50 | 7/10 | 6/10 | MEDIUM 7, SAFE 3 | MEDIUM 6, SAFE 4 |
| skillgate | SKILL.md-only | 3.6 | 0.10 / 0.00 / 0.50 | 0.10 / 0.00 / 0.50 | 2/10 | 2/10 | MEDIUM 2, SAFE 8 | MEDIUM 2, SAFE 8 |

ABSTAIN_ERROR: 8회 실행 160행 중 0건.

건별 (`score verdict`, full-package / SKILL.md-only):

| skill_id | label | origin | cisco | skillspector | skillfortify | skillgate |
|---|---|---|---|---|---|---|
| stb:case_04866 | 1 | injected | 0.75 UNSAFE / 0.75 UNSAFE | 0.82 DO_NOT_INSTALL / 0.00 CAUTION | 0.00 SAFE / 0.00 SAFE | 0.50 MEDIUM / 0.00 SAFE |
| stb:case_03510 | 1 | injected_d11 | 1.00 UNSAFE / 0.50 SAFE | 0.34 CAUTION / 0.00 CAUTION | 0.00 SAFE / 0.00 SAFE | 0.00 SAFE / 0.00 SAFE |
| stb:case_02130 | 1 | injected | 1.00 UNSAFE / 0.75 UNSAFE | 0.97 DO_NOT_INSTALL / 0.08 CAUTION | 0.75 UNSAFE / 0.75 UNSAFE | 0.50 MEDIUM / 0.00 SAFE |
| stb:case_02309 | 1 | injected | 1.00 UNSAFE / 0.00 SAFE | 1.00 DO_NOT_INSTALL / 0.03 CAUTION | 0.75 UNSAFE / 0.75 UNSAFE | 0.50 MEDIUM / 0.50 MEDIUM |
| stb:case_02213 | 1 | injected | 0.75 UNSAFE / 0.00 SAFE | 0.28 CAUTION / 0.12 CAUTION | 0.00 SAFE / 0.00 SAFE | 0.00 SAFE / 0.00 SAFE |
| stb:case_02926 | 1 | injected | 1.00 UNSAFE / 0.00 SAFE | 1.00 DO_NOT_INSTALL / 0.05 CAUTION | 0.75 UNSAFE / 0.75 UNSAFE | 0.50 MEDIUM / 0.50 MEDIUM |
| stb:case_00177 | 1 | injected | 1.00 UNSAFE / 0.00 SAFE | 0.45 CAUTION / 0.00 CAUTION | 0.75 UNSAFE / 0.75 UNSAFE | 0.50 MEDIUM / 0.00 SAFE |
| stb:case_01986 | 1 | injected | 1.00 UNSAFE / 0.00 SAFE | 1.00 DO_NOT_INSTALL / 0.16 CAUTION | 0.00 SAFE / 0.00 SAFE | 0.50 MEDIUM / 0.00 SAFE |
| stb:case_04086 | 1 | injected | 1.00 UNSAFE / 0.75 UNSAFE | 1.00 DO_NOT_INSTALL / 0.00 CAUTION | 0.00 SAFE / 0.00 SAFE | 0.50 MEDIUM / 0.00 SAFE |
| stb:case_04589 | 1 | injected_d11 | 1.00 UNSAFE / 0.75 UNSAFE | 0.34 CAUTION / 0.00 CAUTION | 0.00 SAFE / 0.00 SAFE | 0.00 SAFE / 0.00 SAFE |
| stb:case_01984 | 0 | safe_pool | 0.00 SAFE / 0.00 SAFE | 0.00 CAUTION / 0.00 CAUTION | 0.75 UNSAFE / 0.75 UNSAFE | 0.00 SAFE / 0.00 SAFE |
| stb:case_03798 | 0 | injected_d8 | 1.00 UNSAFE / 0.00 SAFE | 0.54 DO_NOT_INSTALL / 0.00 CAUTION | 0.75 UNSAFE / 0.75 UNSAFE | 0.50 MEDIUM / 0.50 MEDIUM |
| stb:case_03189 | 0 | injected_d8 | 0.00 SAFE / 0.00 SAFE | 0.38 CAUTION / 0.06 CAUTION | 0.00 SAFE / 0.00 SAFE | 0.00 SAFE / 0.00 SAFE |
| stb:case_00420 | 0 | safe_pool | 0.50 SAFE / 0.00 SAFE | 0.11 CAUTION / 0.06 CAUTION | 0.00 SAFE / 0.00 SAFE | 0.50 MEDIUM / 0.00 SAFE |
| stb:case_00501 | 0 | safe_pool | 0.25 SAFE / 0.00 SAFE | 0.07 CAUTION / 0.07 CAUTION | 0.75 UNSAFE / 0.75 UNSAFE | 0.50 MEDIUM / 0.00 SAFE |
| stb:case_03981 | 0 | safe_pool | 0.00 SAFE / 0.00 SAFE | 0.42 CAUTION / 0.42 CAUTION | 0.00 SAFE / 0.00 SAFE | 0.00 SAFE / 0.00 SAFE |
| stb:case_03650 | 0 | safe_pool | 0.00 SAFE / 0.00 SAFE | 0.00 CAUTION / 0.00 CAUTION | 0.00 SAFE / 0.00 SAFE | 0.00 SAFE / 0.00 SAFE |
| stb:case_00957 | 0 | safe_pool | 1.00 UNSAFE / 0.00 SAFE | 0.89 DO_NOT_INSTALL / 0.13 CAUTION | 0.00 SAFE / 0.00 SAFE | 0.50 MEDIUM / 0.00 SAFE |
| stb:case_05087 | 0 | safe_pool | 0.50 SAFE / 0.00 SAFE | 0.19 SAFE / 0.00 CAUTION | 0.75 UNSAFE / 0.75 UNSAFE | 0.50 MEDIUM / 0.50 MEDIUM |
| stb:case_04543 | 0 | safe_pool | 1.00 UNSAFE / 0.00 SAFE | 0.52 DO_NOT_INSTALL / 0.00 CAUTION | 0.00 SAFE / 0.00 SAFE | 0.50 MEDIUM / 0.00 SAFE |

20건에서 읽을 수 있는 것 (일반화하지 않는다):

- **입력 조건이 결과를 뒤집는다.** SkillTrustBench의 injected 공격은 대부분 `scripts/`에 있어서, SKILL.md만 주면 Cisco 재현율이 10/10에서 4/10으로, SkillSpector는 6/10에서 0/10으로, SkillGate는 7/10에서 2/10으로 떨어진다. MaliciousSkillBench 비교(SKILL.md-only)와 패키지 단위 비교를 한 표에 섞으면 안 되는 이유다.
- **SkillFortify는 두 조건이 완전히 같다.** SKILL.md만 읽는다는 R3의 관찰이 20건에서 그대로 확인됐다.
- **SkillFortify와 SkillGate(prefilter)는 malicious와 normal의 점수 분포가 같다** (평균 0.30/0.30, 0.35/0.30). 이 20건에서는 라벨을 구분하지 못한다. 논문의 SkillFortify Source-Disjoint FPR 0.499, SkillGate prefilter-only FPR 27.1%(SkillGate 논문 Table VI B1)와 방향이 같다.
- `stb:case_03798`은 라벨이 normal(origin `injected_d8`)인데 네 도구 전부가 full-package에서 잡았다. SkillTrustBench의 `injected_d8`/`suspicious` 계열 라벨은 평가 전에 대표가 한 번 더 확인할 것.
- SkillSpector의 `CAUTION`은 점수 0에도 붙는다(SKILL.md-only 20건 전부가 CAUTION이고 그중 10건은 점수 0). 게이트는 `recommendation`과 `score`를 구분해서 쓴다(§2 함정).

## 6. 전체 실행 계획 (MaliciousSkillBench 9,740건)

입력은 HF `ProtectSkills/MaliciousSkillBench` `primary`의 `skill_text`를 `data/raw/MaliciousSkillBench/text/<benchmark_id>/SKILL.md`로 저장한 것(`data/build_manifest.py`가 기대하는 레이아웃). 조건은 `--skill-md-only`. 배치는 200(SkillSpector는 자동으로 32, SkillFortify는 1).

예상 시간은 200건 SKILL.md-only 실측(§6.1)을 9,740건으로 선형 외삽한 것이다. 상한으로 읽는다.

### 6.1 200건 실측 (SkillTrustBench 100 malicious + 100 normal, SKILL.md-only, 배치 200)

같은 PC, 순서대로 한 번씩. 결과 파일은 `runs/smoke_stb200/`. 게이트는 §3의 1차 게이트.

| 도구 | 200건 벽시계(초) | 건당(초) | 9,740건 예상 | 배치 | ABSTAIN_ERROR | 게이트 재현율 (100 malicious) | 게이트 FPR (100 normal) |
|---|---|---|---|---|---|---|---|
| cisco | 35.3 | 0.18 | 약 29분 | 200 × 1 | 0 | 32/100 | 0/100 |
| skillspector | 209.5 | 1.05 | 약 170분 (2.8시간) | 32 × 7 | 0 | 5/100 (CAUTION+ `score > 0.2`: 20/100) | 0/100 (CAUTION+: 11/100) |
| skillfortify | 67.1 | 0.34 | 약 54분 | 1 × 200 | 0 | 36/100 | 36/100 |
| skillgate | 45.2 | 0.23 | 약 37분 | 200 × 1 | 0 | 27/100 | 24/100 |

네 도구 순서대로 돌리면 약 5시간이다. SkillSpector가 절반 이상을 차지한다. 하룻밤이면 끝난다.

SkillSpector의 첫 200건 실행(배치 200)은 32건 예산 때문에 168건이 `omitted`(`omitted_count: 168`) 한 항목으로 나왔고, 당시 코드(omitted 항목 guard 없음)는 `KeyError`로 그 배치 전체를 `ABSTAIN_ERROR:tool_failed`로 기록했다(200/200). 현재 코드는 omitted 항목을 건너뛰므로 같은 상황에서 32건 정상 + 168건 `ABSTAIN_ERROR:no_result`가 된다. 어느 쪽이든 정상으로 둔갑한 행은 없다. 이 실행의 raw stdout은 보존되지 않았다. 배치를 32로 자른 뒤 다시 돌린 것이 위 표다. 실패는 눈에 보이게 남는다는 것을 확인한 셈이다.

### 6.2 일정 제안 (미팅에서 확정)

| 순서 | 일 | 담당 제안 | 주차 | 근거 |
|---|---|---|---|---|
| 1 | HF `primary` 내려받아 `text/<benchmark_id>/SKILL.md` 생성, `data/manifest.csv` 재생성 | 대표 | 2주차 (9/28~10/4) | 데이터와 manifest는 대표 소유 (`docs/data-format.md`) |
| 2 | 네 도구 SKILL.md-only 전체 실행 (밤에 순서대로, 한 PC) | 대표 | 2주차 | 도구 넷 다 로컬이고 API 키가 없다. 결과는 `runs/baseline_<tool>_<날짜>.csv` |
| 3 | Source-Disjoint test 1,384건 조인, Macro-F1 / recall / FPR 표 | 대표 | 3주차 | `eval/evaluate.py`에 MaliciousSkillBench 형식 지표 추가 필요 |
| 4 | 우리 1단계 결과 옆에 놓기 | 1단계 담당 팀원 | 3주차 | 1단계가 `predictions.csv`를 내는 시점 |
| 5 | (선택) MalSkillBench 패키지 단위 full-package 실행 | 미정 | 4주차 이후 | benign 4,000 + malicious 3,944, 스크립트 포함. 시간이 §6.1의 약 두 배 이상 |

배치 200으로 돌리면 도구 크래시 한 번에 200건만 `ABSTAIN_ERROR`가 되고, `runs/*.raw/batch_NNNN.*`로 어느 배치인지 바로 찾는다. 실패 배치는 `--limit`과 매니페스트 슬라이스로 다시 돌린다.

## 7. 하지 말 것

- 게이트나 임계값을 validation으로 튜닝하지 않는다. 논문이 정한 게이트를 그대로 쓴다(G.4, J.2 "no post-hoc best-threshold selection is performed").
- 실패를 정상으로 바꾸지 않는다. `ABSTAIN_ERROR`는 분모에서 빼고 coverage를 따로 적는다.
- full-package 결과와 SKILL.md-only 결과를 한 표에 섞지 않는다. 표마다 조건을 적는다.
- 스캔을 위해 스킬 frontmatter나 본문을 고치지 않는다. 임시 복사본은 원본 그대로 두고, 디렉터리명만 `skill_id`에서 만든다(`:` → `__`, `/`와 `\` → `_`).
- 스킬을 실행하지 않는다. 네 도구 모두 정적 분석이지만, 임시 디렉터리에 `scripts/`가 복사되므로 그 안에서 아무것도 실행하지 않는다 (`RESPONSIBLE_USE.md`: "Do not execute untrusted Skills").
- Snyk agent-scan이나 다른 클라우드 API로 벤치마크 본문을 보내지 않는다.
- `runs/`와 `data/raw/`는 git에 올리지 않는다(`.gitignore`). `runs/*.raw/`에는 도구가 인용한 스킬 본문 스니펫이 들어 있다.
- 논문 수치를 우리 수치처럼 쓰지 않는다. 우리가 돌린 버전(Cisco 2.1.0, SkillSpector 2.12.0 `c7958a3`, SkillFortify 0.6.0, SkillGate 0.1.0 `c1641c5`)과 함께 적는다.
- SkillTrustBench(CC-BY-NC-SA-4.0)와 MalSkillBench(academic research only) 본문을 재배포하지 않는다. 스모크 매니페스트에는 경로와 라벨만 있다.

## 8. URL

- MaliciousSkillBench 저장소 https://github.com/protectskills/MaliciousSkillBench (`scanner_eval/README.md`, `scanner_eval/source_disjoint_results.csv`, `evaluation/metrics.py`, `metadata/splits/source_disjoint.csv`, `RESPONSIBLE_USE.md`)
- MaliciousSkillBench 논문 https://arxiv.org/abs/2608.19901 (부록 G.4, J.1, J.2, Table 45)
- MaliciousSkillBench 데이터 https://huggingface.co/datasets/ProtectSkills/MaliciousSkillBench
- Cisco skill-scanner https://github.com/cisco-ai-defense/skill-scanner , https://pypi.org/project/cisco-ai-skill-scanner/
- NVIDIA SkillSpector https://github.com/NVIDIA/SkillSpector (README "Risk Scoring", "Exit codes")
- SkillFortify https://github.com/qualixar/skillfortify , https://pypi.org/project/skillfortify/ , 논문 https://arxiv.org/abs/2603.00195
- SkillGate 코드 https://github.com/awsm-research/skillgate , 논문 https://arxiv.org/abs/2607.25619
- Snyk agent-scan https://github.com/snyk/agent-scan (README "Quick start", 대량 스캔 문구)
- SkillTrustBench (스모크 데이터) `data/raw/SkillTrustBench/benchmark_full_v1.0/ground_truth.json`
- 조사 원문: 스크래치패드 `research/R3_baselines.md`(설치·출력 실측), `research/R4_eval_protocol.md`(프로토콜 비교)

## 추가 (2026-09-26): 논문 부록 J의 전체 벤치마크 수치

우리 기준선 결과를 옆에 놓을 숫자다(원문 확인, `wiki/sources.md`). 조건은 SKILL.md 단일 사본, 사전 등록 게이트, 논문의 고정 환경(Cisco 커밋 48f59347, yara-x 1.4.0).

| 스캐너 | 전체 9,740 재현율 / FPR / Macro-F1 (Table 43) | Source-Disjoint 재현율 / FPR / Macro-F1 (Table 44) |
|---|---|---|
| Cisco-local-behavioral | .064 / .008 / .254 | .025 / .011 / .308 |
| SkillFortify-offline | .566 / .451 / .516 | .253 / .499 / .349 |
| SkillSpector-static | .033 / .002 / .222 | .000 / .006 / .281 |

부록 J.4는 공격 범주별 재현율도 보고한다(Figure 6). 우리가 앞서 "없다"고 적은 것은 틀렸다. 논문 스스로 "Differences are descriptive and may reflect source composition as well as scanner behavior"라고 한정한다.
