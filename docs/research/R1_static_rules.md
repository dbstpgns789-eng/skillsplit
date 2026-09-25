# R1. Stage 1(정적 규칙) 재사용 가능한 규칙 소스와 AST 도구 인벤토리

조사일: 2026-09-25. 모든 수치는 `gh api`로 저장소 원문을 내려받아 직접 센 것이다. 세는 방법을 함께 적었으므로 재현 가능하다. 우리 저장소는 MIT이므로 "MIT 프로젝트에 포함 가능한가"를 기준으로 판정했다.

라이선스 판정 기준 (요약):
- MIT / Apache-2.0 / BSD / DRL 1.1: 규칙 파일을 복사해 포함 가능. 단 원 라이선스 고지와 저작권 표시를 유지한다. Apache-2.0은 변경 사실 표시(4(b))와 NOTICE 승계(4(d))가 추가로 필요하다.
- GPL / AGPL: 코드를 링크하거나 복사하면 우리 코드도 같은 라이선스를 따라야 한다. 정규식 문자열 하나가 저작물인지는 다툼이 있지만, 이 과제는 "안전한 쪽"을 택한다. **AGPL/GPL 소스에서는 규칙을 복사하지 않는다.** 바이너리를 외부 도구로 실행해 결과만 비교하는 것은 문제없다.
- 라이선스 파일 없음: 재사용 불가.

---

## 0. 한눈에 보기

| # | 소스 | SPDX | 규칙 형식 | 규칙 수 (직접 셈) | 대상 | MIT 프로젝트 재사용 |
|---|---|---|---|---|---|---|
| 1 | awsm-research/skillgate | MIT | Python 튜플 리스트 + YAML | 428 (ATT&CK) + 105 (Sigma 변환) = 533; YAML 16 | 셸 명령·경로·인코딩, SKILL.md 지시문 | 가능. Sigma 유래 105건은 DRL 1.1 귀속 필요 |
| 2 | cisco-ai-defense/skill-scanner | Apache-2.0 | YAML 시그니처 + YARA + Python | core 46 sig(138 regex) + 27 YARA + 116 Python; ATR 712 sig(3,107 regex); promptguard 26 sig(47 regex) | SKILL.md·스크립트 전체 | 가능 (Apache 고지 유지) |
| 2b | Agent-Threat-Rule/agent-threat-rules (Cisco ATR 팩의 원본) | MIT | YAML (ATR 스키마) | rules/ 아래 YAML 825개 (README는 "777 live rules") | LLM 입출력·SKILL.md·MCP | 가능 |
| 3 | gitleaks/gitleaks | MIT | TOML `[[rules]]` | 222 | 비밀키·토큰 리터럴 | 가능 |
| 4 | trufflesecurity/trufflehog | AGPL-3.0 | Go 소스 코드 (데이터 파일 아님) | 886 detector 디렉터리 | 비밀키 + 실시간 검증 | **복사 불가.** 외부 바이너리 실행만 |
| 5 | SigmaHQ/sigma | DRL 1.1 (규칙) | YAML (Sigma) | 전체 3,144; linux 210, macos 69 | 프로세스 생성 로그 | 가능 (author·링크·DRL 고지 유지) |
| 6 | NVIDIA/SkillSpector | Apache-2.0 | Python `(regex, confidence)` 튜플 + YARA | regex 튜플 약 603 (15개 파일), YARA 20 | SKILL.md·스크립트 | 가능 (Apache 고지 유지) |
| 6b | Jibberdaffle12/openclaw-skillscan | MIT | bash 배열 (고정 문자열) | BLOCKER 21 + WARNING 11 + DOC 7+2 | 문자열 grep | 가능하지만 가치 낮음 |
| 6c | anikrahman0/security-skill-scanner | MIT | JS regex 배열 | 카테고리 11개, regex 약 50 | SKILL.md | 가능하지만 가치 낮음 |
| 6d | jason-allen-oneal/openclaw-skill-scanner | 라이선스 없음 | Cisco 스캐너 래퍼 | 자체 규칙 0 | - | **불가 (라이선스 없음), 규칙도 없음** |
| 7a | bashlex | GPL-3.0+ | Python 라이브러리 | - | 셸 파싱 | **불가 (GPL)**. 유지보수 중단, 파싱 실패 확인 |
| 7b | py-tree-sitter + tree-sitter-bash/python | MIT | Python 바인딩 + C 문법 | - | 셸·Python AST | 가능 |
| 7c | Python stdlib `ast` | PSF-2.0 | 표준 라이브러리 | - | Python AST | 가능 |

---

## 1. SkillGate (arXiv 2607.25619)

### 1.1 논문과 저장소
- 논문: https://arxiv.org/abs/2607.25619 (SkillGate: Cost Efficient Runtime Malicious Skill File Detection in Coding Agents; Rui Yang, Michael Fu, Kla Tantithamthavorn, Chetan Arora, Joey Chua)
- HTML 본문: https://arxiv.org/html/2607.25619 에서 저장소 URL 확인.
- 저장소: https://github.com/awsm-research/skillgate (GitHub API license: `MIT`, LICENSE 첫 줄 "MIT License / Copyright (c) 2026 Agentic Worlds for Software Makers (AWSM) Research Group", 마지막 push 2026-07-28, star 1)
- 데이터셋: https://huggingface.co/datasets/zenith6888/SkillsBench-1650

논문 원문 (HTML 본문에서 발췌):
> "The RuleEngine compiles 530 patterns into an AttackPatternMatcher and scans the extracted skill file content: 428 core patterns systematically derived from the MITRE ATT&CK framework, plus 102 community rules imported from the Sigma detection format."

> "we release the full implementation, the 530-pattern ruleset, and our evaluation harness as open source."

### 1.2 규칙 파일 위치와 형식
| 파일 | 형식 | 개수 (직접 셈) |
|---|---|---|
| `skillgate/classifier/attack_patterns.py` | Python 리스트 `ATTACK_PATTERNS: list[tuple[str, str, Severity, str, str, str \| None]]` = (id, regex, severity, description, category, mitre_id) | **428** (`ast.parse` 후 `len(ATTACK_PATTERNS.elts)`) |
| `skillgate/classifier/sigma_patterns.py` | 같은 튜플 형식, 헤더 "Auto-generated from SigmaHQ rules (Linux + macOS process creation)" | **105** (같은 방법) |
| `skillgate/classifier/attack_patterns.py` 내 `SAFE_PATTERNS` | (id, regex) 튜플, 오탐 억제용 | 135 |
| `rules/default.yaml` | YAML `rules: [{id, pattern, severity, category, description}]` | 6 |
| `rules/skills.yaml` | 같은 YAML 형식, SKILL.md 지시문 대상 | 10 |

**주의: 저장소의 실제 수는 428 + 105 = 533이다. 논문의 "530 (428 + 102)"과 3건 차이가 난다.** 보고서에서 SkillGate 수치를 인용할 때는 "논문 기준 530, 저장소 main 브랜치(2026-07-28 push) 기준 533"으로 병기한다.

`ATTACK_PATTERNS`의 category 분포 (직접 셈): defense_evasion 62, execution 56, risky_command 56, credential_access 44, persistence 38, impact 33, obfuscation 27, exfiltration 27, discovery 23, command_and_control 21, privilege_escalation 17, collection 8, container 5, encoding 4, network 2, cloud 2, injection 2, path 1. 논문 Table의 상위 12개 분포와 일치한다.

프롬프트 인젝션 관련은 `injection` 카테고리 2건(INJ006 ChatML 토큰, INJ007 LLaMA 토큰)뿐이고, "ignore previous instructions"류 자연어 패턴은 `attack_patterns.py`에 없다. 자연어 지시문 규칙은 `rules/skills.yaml` 10건이 전부다. 즉 SkillGate 규칙은 **셸 명령 중심**이다.

### 1.3 예시 규칙 (verbatim, `attack_patterns.py`)
```python
("RCE001", r"curl\s+[^\|;]*\|\s*(?:ba|z|da|a)?sh", Severity.CRITICAL,
 "Remote code execution: curl piped to shell", "execution", "T1059.004"),
("RCE010", r"base64\s+-d[^\|]*\|\s*(?:ba|z|da|a)?sh", Severity.CRITICAL,
 "Base64 decoded execution", "execution", "T1140"),
("CRED010", r"\.aws/credentials", Severity.CRITICAL,
 "AWS credentials file access", "credential_access", "T1552.001"),
("EXFIL120", r"\bbase64\b[^\n]*\|\s*(?:curl|wget|nslookup|dig)\b", Severity.HIGH,
 "Base64-encoded data piped to network command (DNS/HTTP exfil)", "exfiltration", "T1132.001"),
```
`rules/skills.yaml` (verbatim):
```yaml
  - id: SKILL_INJ001
    pattern: "never\\s+tell\\s+the\\s+user"
    severity: HIGH
    category: skill
    description: "Skill instructs to hide information from user"
```
`sigma_patterns.py` (verbatim; Sigma의 `contains` 리스트를 lookahead 정규식으로 변환한 형태):
```python
("SIGMA033", r"(?=.*import)(?=.*base64)(?=.*\\ \\-c).*", Severity.HIGH,
 "Detects execution of the python binary with the '-c' flag and base64 ...", "execution", ...),
```

### 1.4 라이선스 판정
- 저장소 전체 MIT → `attack_patterns.py`, `rules/*.yaml` 복사 가능. 저작권 고지("Copyright (c) 2026 Agentic Worlds for Software Makers (AWSM) Research Group") 유지.
- **단, `sigma_patterns.py` 105건은 SigmaHQ 규칙에서 자동 변환된 것**이고 원본은 DRL 1.1이다. SkillGate 파일은 원 규칙의 `author` 필드를 보존하지 않고 있다(파일 헤더에 "Source: https://github.com/SigmaHQ/sigma"만 있음). DRL 1.1은 공유 시 author 식별, 원 규칙 링크, DRL 고지를 요구한다(5절 참조). 우리가 이 105건을 쓴다면 SkillGate 경유가 아니라 **SigmaHQ 원본에서 직접 가져와 author와 rule id를 보존**하는 편이 안전하다.

---

## 2. cisco-ai-defense/skill-scanner

- 저장소: https://github.com/cisco-ai-defense/skill-scanner (star 2,549, 마지막 push 2026-09-24)
- GitHub API의 license 필드는 `NOASSERTION`이지만 LICENSE 파일 원문은 Apache-2.0이다: "Apache License / Version 2.0, January 2004 / Copyright 2026 Cisco Systems, Inc. and its affiliates". README 배지도 Apache 2.0. → **SPDX: Apache-2.0**
- PyPI 패키지명: `cisco-ai-skill-scanner` (README "pip install cisco-ai-skill-scanner")

### 2.1 규칙 파일 위치와 개수
세 개의 규칙 팩(pack)이 `skill_scanner/data/packs/` 아래에 있다. 개수는 각 YAML을 `yaml.safe_load`로 읽어 rule 항목 수와 `patterns:` 리스트 원소 수를 합산한 것이다.

**(a) core 팩** `skill_scanner/data/packs/core/`
| 종류 | 경로 | 개수 |
|---|---|---|
| YAML 시그니처 | `signatures/*.yaml` 11개 파일 | 46 rules / 138 regex |
| YARA | `yara/*.yara` 16개 파일 | 27 rules (`behavior_chain_detection.yara` 9, `embedded_binary_detection.yara` 4, 나머지 14파일 각 1) |
| Python 규칙 | `python/*_checks.py` 13개 파일 | pack.yaml 등록 기준 116 |
| 등록 총계 | `core/pack.yaml` `rules:` 항목 | **189** (signature 46, python 116, yara 27) |

signatures 파일별: command_injection 12/43, data_exfiltration 8/35, hardcoded_secrets 8/10, obfuscation 4/7, prompt_injection 5/17, resource_abuse 3/7, unauthorized_tool_use 3/16, harmful_content 1/1, malware 1/1, supply_chain 1/1, social_engineering 0/0 (rules/regex).

**(b) ATR 팩** `skill_scanner/data/packs/atr/signatures/` 10개 파일 → **712 rules / 3,107 regex**. README(`packs/atr/README.md`) 원문: "**Source:** Agent Threat Rules (ATR) ... **ATR Version:** 3.5.6 **Rules:** 712 signatures across 10 signature files **License:** MIT". 파일 헤더: "Auto-generated by convert-to-skill-scanner.mjs — do not edit manually". 파일별: atr_prompt_injection 242/1038, atr_context_exfiltration 111/438, atr_agent_manipulation 106/538, atr_tool_poisoning 90/393, atr_skill_compromise 45/195, atr_privilege_escalation 42/158, atr_model_abuse 37/121, atr_excessive_autonomy 31/159, atr_data_poisoning 5/48, atr_model_security 3/19.

**(c) promptguard 팩** `skill_scanner/data/packs/promptguard/signatures/` 3개 파일 → 26 rules / 47 regex (markdown_exfiltration 6, pii_detection 8, secret_providers 12). README: PR #89로 직접 기여된 것이며 별도 원본 저장소는 비공개. 저장소 안의 기여이므로 Apache-2.0.

### 2.2 시그니처 YAML 형식 (docs/architecture/analyzers/writing-custom-rules.md)
필드: `id`(필수), `patterns`(필수, regex 리스트, 하나라도 매치되면 발화), `severity`(CRITICAL/HIGH/MEDIUM/LOW/INFO), `category`, `description`, `exclude_patterns`(선택, 매치 억제), `file_types`(선택, `python`, `bash`, `markdown` 등; 생략 시 전체), `remediation`.
URL: https://github.com/cisco-ai-defense/skill-scanner/blob/main/docs/architecture/analyzers/writing-custom-rules.md

### 2.3 예시 규칙 (verbatim)
`signatures/command_injection.yaml` (https://github.com/cisco-ai-defense/skill-scanner/blob/main/skill_scanner/data/packs/core/signatures/command_injection.yaml):
```yaml
- id: COMMAND_INJECTION_USER_INPUT
  category: command_injection
  severity: HIGH
  patterns:
    # eval with positional arguments (the most dangerous pattern)
    # This is the primary vector for shell command injection
    - "eval\\s+[\"']?\\$[0-9@*]"
    - "eval\\s+[\"']?\\$\\{[0-9@*]"
  exclude_patterns:
    # Testing/example context
    - "example"
    - "test"
    - "#.*eval"
  file_types: [bash]
  description: "eval with user-controlled input - command injection risk"
  remediation: "Never use eval with user input. Use safer alternatives like case statements or parameter validation"
```
`signatures/prompt_injection.yaml`:
```yaml
- id: PROMPT_INJECTION_UNRESTRICTED_MODE
  category: prompt_injection
  severity: HIGH
  patterns:
    - "(?i)you are now in\\s+(unrestricted|debug|developer|admin|god|jailbreak)\\s+mode"
    - "(?i)enter\\s+(unrestricted|debug|developer)\\s+mode"
    - "(?i)disable\\s+(all\\s+)?(safety|security|content|ethical)\\s+(filters|checks|guidelines)"
  file_types: [markdown]
  description: "Attempts to enable unrestricted or dangerous modes"
  remediation: "Remove mode-switching instructions that bypass safety"
```
`signatures/data_exfiltration.yaml` (DATA_EXFIL_HTTP_POST, 일부):
```yaml
- id: DATA_EXFIL_HTTP_POST
  category: data_exfiltration
  severity: CRITICAL
  patterns:
    - "(?i)requests\\.post\\s*\\([^\\n)]{0,240}(?:attacker|evil|webhook|exfil|steal|leak|collect|backup_endpoint|analytics_endpoint|discord\\.com/api/webhooks|pastebin|telegram)"
  file_types: [python]
```
`yara/code_execution_generic.yara` (base64 + exec 체인 문자열):
```yara
$obfuscated_exec = /\b(base64\.(b64)?decode|atob|decode\(['"]base64['"]\))\s*\([^)]+\)[^}]{0,50}\b(eval|exec|os\.system|subprocess)\s*\(/i
```
`yara/credential_harvesting_generic.yara`:
```yara
$credential_file_access = /\b(open|read)\s*\(\s*['\"]?\s*(~\/\.ssh\/id_rsa|~\/\.ssh\/id_dsa|~\/\.ssh\/id_ecdsa|~\/\.aws\/credentials|\/etc\/shadow|~\/\.netrc|~\/\.pgpass)\b/i
```

### 2.4 SKILL.md와 스크립트를 어떻게 다루는가
docs/architecture/analyzers/static-analyzer.md (https://github.com/cisco-ai-defense/skill-scanner/blob/main/docs/architecture/analyzers/static-analyzer.md)의 단계 표:
- `_scan_instruction_body()` : "SKILL.md content against signature rules"
- `_scan_scripts()` : "Python/bash/other scripts against signatures"
- `_scan_referenced_files()` : "Files mentioned in SKILL.md instructions"
- `_yara_scan()` : "YARA-X rule matches across all eligible files"
- `check_active_remote_execution()` : "Active remote payload acquisition joined to execution"

파일 유형 판별은 `skill_scanner/core/rules/patterns.py`: `_CODE_SUFFIXES = frozenset({".bash", ".js", ".py", ".sh", ".ts", ".zsh"})`, `path.name.lower() == "skill.md"`로 SKILL.md 식별. 규칙의 `file_types`가 `bash`/`python`/`markdown`으로 스코프를 나눈다.

정책(`skill_scanner/data/default_policy.yaml` `rule_scoping:`)으로 문서 경로 강등이 있다:
```yaml
rule_scoping:
  # Rules that ONLY fire on SKILL.md and script files (.py, .sh, etc.)
  skillmd_and_scripts_only:
    - "coercive_injection_generic"
    - "autonomy_abuse_generic"
  # Rules that are skipped for files in documentation directories
  skip_in_docs:
    - "code_execution_generic"
    ...
    - "PROMPT_INJECTION_IGNORE_INSTRUCTIONS"
```
즉 Cisco도 우리와 같은 문제(SKILL.md는 문서이면서 지시문)를 `file_types` + `skip_in_docs`로 다룬다.

### 2.5 CLI 출력 형식 (베이스라인으로 쓸 때)
docs/reference/output-formats.md (https://github.com/cisco-ai-defense/skill-scanner/blob/main/docs/reference/output-formats.md): `--format summary|json|markdown|table|sarif|html`, `--output PATH`, `--compact`. 정식 JSON Schema 파일은 없다(저장소에 `evals/expectation.schema.json`과 LLM 응답용 `llm_response_schema.json`만 있음). 대신 `skill_scanner/core/models.py`의 `Finding` dataclass가 사실상의 스키마다:
```python
class Finding:
    id: str  # Unique finding identifier (e.g., rule ID + line number)
    rule_id: str  # Rule that triggered this finding
    category: ThreatCategory
    severity: Severity
    title: str
    description: str
    file_path: str | None = None
    line_number: int | None = None
    snippet: str | None = None
    remediation: str | None = None
    analyzer: str | None = None  # Which analyzer produced this finding (e.g., "static", "llm", "behavioral")
    metadata: dict[str, Any] = field(default_factory=dict)
```
문서의 JSON 샘플 최상위 키: `skill_name, skill_path, is_safe, max_severity, findings_count, findings[], scan_duration_seconds, duration_ms, analyzers_used[], timestamp, scan_metadata{policy_name,...}, llm_usage{}`(LLM 사용 시만).
베이스라인 실행 예: `skill-scanner scan /path/to/skill --format json --output out.json` (정적 전용은 옵션 없이 기본: "core analyzers: static + bytecode + pipeline + correlation").

### 2.6 라이선스 판정
Apache-2.0. MIT 프로젝트에 포함 가능. 조건: LICENSE 사본 포함, 복사한 파일에 Cisco 저작권·Apache 고지 유지, 수정 시 수정 사실 표기. ATR 팩은 MIT(원본 Agent-Threat-Rule). promptguard는 Apache-2.0.

### 2.7 (참고) 원본 ATR 저장소
- https://github.com/Agent-Threat-Rule/agent-threat-rules (SPDX MIT, LICENSE "Copyright (c) 2026 ATR Contributors", star 399, push 2026-09-24)
- `rules/` 아래 YAML 825개 (git tree 기준; 디렉터리별 prompt-injection 250, context-exfiltration 133, tool-poisoning 113, agent-manipulation 108, privilege-escalation 76, skill-compromise 52, model-abuse 41, excessive-autonomy 39, data-poisoning 9, model-security 4). README는 "106 of the 777 live rules"가 `maturity: stable`이라고 적고 있으며(deprecated 제외 수치), "re-derive by parsing before quoting the figure"라고 명시한다.
- 형식: `detection.conditions[] = {field, operator: regex, value, description}`, `condition: any`, `test_cases.true_positives/true_negatives` 동봉. `scan_target: skill` 필드로 SKILL.md 대상 규칙을 구분한다. Cisco ATR README: "all 38 rules carrying `scan_target: skill` are currently `maturity: test`".
- 예시 `rules/context-exfiltration/ATR-2026-00162-skill-credential-exfil-combo.yaml` (verbatim):
```yaml
    - field: content
      operator: regex
      value: '(?i)(?:cat|read)\s+[^\n]*(?:id_rsa|credentials|\.env|secret_key|private_key)[^\n]*\|\s*(?:base64|xxd|gzip)[^\n]*\|\s*(?:curl|wget|nc)'
      description: 'Credential read → encode → exfiltrate pipeline'
```
- 예시 `ATR-2026-00201-credential-pipe-exfiltration.yaml` (author "TYSYS (Wind) — skill-sanitizer project"):
```yaml
      value: "(?i)curl\\s+.{0,100}(-d|--data)\\s+.{0,30}(key|token|secret|password|credential)"
      description: "Curl POST with credential data"
```

---

## 3. gitleaks

- 저장소: https://github.com/gitleaks/gitleaks (SPDX MIT, LICENSE "MIT License / Copyright (c) 2019 Zachary Rice", push 2026-09-23)
- 규칙 파일: `config/gitleaks.toml` (https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml). 헤더: "This file has been auto-generated. Do not edit manually." `minVersion = "v8.25.0"`.
- 형식: TOML. 각 규칙은 `[[rules]]` 블록에 `id, description, regex, entropy, keywords[]`, 선택적으로 `[[rules.allowlists]]`.
- 개수: `grep -c '^\[\[rules\]\]'` = **222**.
- 대상: 비밀 토큰 리터럴(클라우드 키, PAT, API 키, private key 블록). 경로 접근(~/.aws)이나 명령 패턴은 없다. 우리 (c) 가족 중 "하드코딩된 비밀"에만 해당.

예시 (verbatim):
```toml
[[rules]]
id = "aws-access-token"
description = "Identified a pattern that may indicate AWS credentials, risking unauthorized cloud resource access and data breaches on AWS platforms."
regex = '''\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b'''
entropy = 3
keywords = [
    "a3t",
    "akia",
```
```toml
id = "github-pat"
description = "Uncovered a GitHub Personal Access Token, potentially leading to unauthorized repository access and sensitive content exposure."
regex = '''ghp_[0-9a-zA-Z]{36}'''
entropy = 3
keywords = ["ghp_"]
```
```toml
id = "openai-api-key"
regex = '''\b(sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})\b|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})(?:[\x60'"\s;]|\\[nr]|$)'''
entropy = 3
keywords = ["t3blbkfj"]
```
```toml
id = "generic-api-key"
regex = '''(?i)[\w.-]{0,50}?(?:access|auth|(?-i:[Aa]pi|API)|credential|creds|key|passw(?:or)?d|secret|token)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3})(?:[\x60'"\s;]|\\[nr]|$)'''
entropy = 3.5
```
주의: gitleaks 정규식은 Go RE2 문법이다. `(?-i:...)` 같은 인라인 플래그 그룹은 Python `re`에서도 동작하지만(3.6+), `\x60` 등은 그대로 쓸 수 있다. 통째로 가져올 때는 Python `re`로 컴파일 테스트를 한 번 돌린다.

라이선스 판정: MIT → 복사 가능. 저작권 고지 유지.

---

## 4. trufflehog

- 저장소: https://github.com/trufflesecurity/trufflehog (SPDX **AGPL-3.0**, LICENSE 첫 줄 "GNU AFFERO GENERAL PUBLIC LICENSE / Version 3, 19 November 2007", push 2026-09-24)
- 탐지기 형식: **데이터 파일이 아니라 Go 소스 코드**. `pkg/detectors/<name>/<name>.go`마다 `regexp.MustCompile(...)`로 정규식을 박고 `FromData()`에서 HTTP 호출로 실제 유효성까지 검증한다. `pkg/detectors/` 아래 디렉터리 886개 (`gh api .../contents/pkg/detectors` dir 개수). 데이터 형식 파일은 `fp_*.txt` 오탐 단어 목록과 `privatekey/list.txt`뿐.
- 예시 (`pkg/detectors/openai/openai.go`, verbatim):
```go
keyPat = regexp.MustCompile(`\b(sk-(?:(?:proj|svcacct|service)-[A-Za-z0-9_-]+|[a-zA-Z0-9]+)T3BlbkFJ[A-Za-z0-9_-]+)\b`)
```
  (`pkg/detectors/aws/access_keys/accesskey.go`): `idPat = regexp.MustCompile(`\b((?:AKIA|ABIA|ACCA)[A-Z0-9]{16})\b`)`

정직한 재사용성 평가:
1. AGPL-3.0이므로 코드(정규식 리터럴 포함)를 MIT 저장소로 복사하면 안 된다. 정규식 한 줄은 저작물성이 약하다는 주장도 있으나, 이 과제에서 그 논쟁을 감수할 이유가 없다. 같은 정규식이 gitleaks(MIT)에 거의 동일하게 있다(OpenAI 키의 `T3BlbkFJ` 매직 문자열 등).
2. 규칙이 Go 코드에 박혀 있어 데이터로 추출하려면 파서를 짜야 한다. 시간 대비 이득 없음.
3. 강점은 "검증(verify)" 기능인데 우리 stage 1은 오프라인 정적 분석이므로 필요 없다.
→ **결론: 규칙 소스로 쓰지 않는다.** 필요하면 바이너리를 별도 도구로 실행해 결과 비교(베이스라인)만 한다. AGPL은 실행·비교에는 제약이 없다.

---

## 5. Sigma (SigmaHQ/sigma)

- 저장소: https://github.com/SigmaHQ/sigma (GitHub API license `NOASSERTION`; push 2026-09-24)
- 라이선스: 저장소 `LICENSE` 원문: "The rules contained in the SigmaHQ repository (https://github.com/SigmaHQ) are released under the [Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License)". 사양과 로고는 public domain.
- DRL 1.1 전문: https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md . 핵심 조항 (verbatim):
> "Permission is hereby granted, free of charge, to any person obtaining a copy of this rule set and associated documentation files (the "Rules"), to deal in the Rules without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Rules"
> "If you share the Rules (including in modified form), you must retain the following if it is supplied within the Rules: 1. identification of the authors(s) ("author" field) of the Rule ... 2. a URI or hyperlink to the Rule set or explicit Rule ... 3. indicate the Rules are licensed under this Detection Rule License"
> "If you use the Rules (including in modified form) on data, messages based on matches with the Rules must retain ... identification of the authors(s) ("author" field)"

즉 MIT와 유사한 permissive지만 **(1) author 필드, (2) 원 규칙 링크, (3) DRL 고지를 유지**해야 하고, **탐지 메시지에도 author를 남겨야** 한다. 우리 finding 출력에 `source_rule`과 `author` 필드를 넣으면 충족된다.

- 규모 (git tree 기준): `rules/**/*.yml` 3,144; `rules/linux/` 210 (그중 `process_creation/` 122); `rules/macos/` 69 (`process_creation/` 67).
- 우리 가족과 관련된 폴더·파일:
  - (a) curl|sh: `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml`, `proc_creation_lnx_curl_usage.yml`, `proc_creation_lnx_curl_wget_exec_tmp.yml`, `rules/linux/file_event/file_event_lnx_wget_download_file_in_tmp_dir.yml`, `rules/macos/process_creation/proc_creation_macos_nscurl_usage.yml`
  - (b) base64: `proc_creation_lnx_base64_execution.yml`, `proc_creation_lnx_base64_decode.yml`, `proc_creation_lnx_base64_shebang_cli.yml`, `proc_creation_lnx_python_base64_encoded_execution.yml`, `rules/macos/process_creation/proc_creation_macos_base64_decode.yml`, `proc_creation_macos_tail_base64_decode_from_image.yml`
  - (c) credential access: `rules/macos/process_creation/proc_creation_macos_creds_from_keychain.yml`, `proc_creation_macos_find_cred_in_files.yml`, `rules/linux/auditd/execve/lnx_auditd_find_cred_in_files.yml`, `proc_creation_lnx_susp_script_interpretor_spawn_credential_scanner.yml`, `proc_creation_lnx_susp_history_recon.yml`
  - (d) exfil: `proc_creation_lnx_susp_curl_fileupload.yml`, `rules/linux/auditd/execve/lnx_auditd_data_exfil_wget.yml`
- Sigma에는 `~/.aws`, `~/.ssh/id_rsa` 경로 규칙이 사실상 없다(grep 결과 위 파일들뿐). 이 부분은 SkillGate CRED*/Cisco/ATR로 채운다.

예시 (verbatim) `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml`:
```yaml
title: Linux Shell Pipe to Shell
id: 880973f3-9708-491c-a77b-2a35a1921158
status: test
description: Detects suspicious process command line that starts with a shell that executes something and finally gets piped into another shell
author: Florian Roth (Nextron Systems)
date: 2022-03-14
modified: 2022-07-26
tags:
    - attack.stealth
    - attack.t1140
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        CommandLine|startswith:
            - 'sh -c '
            - 'bash -c '
    selection_exec:
        - CommandLine|contains:
              - '| bash '
              - '| sh '
              - '|bash '
              - '|sh '
        - CommandLine|endswith:
              - '| bash'
              - '| sh'
              - '|bash'
              - ' |sh'
    condition: all of selection*
falsepositives:
    - Legitimate software that uses these patterns
level: medium
```
`proc_creation_lnx_base64_execution.yml` (author pH-T (Nextron Systems), id ba592c6d-6888-43c3-b8c6-689b8fe47337):
```yaml
detection:
    selection_base64:
        CommandLine|contains: 'base64 '
    selection_exec:
        - CommandLine|contains:
              - '| bash '
              - '| sh '
              - '|bash '
              - '|sh '
        - CommandLine|endswith:
              - ' |sh'
              - '| bash'
              - '| sh'
              - '|bash'
    condition: all of selection_*
```
`rules/macos/process_creation/proc_creation_macos_creds_from_keychain.yml` (author Tim Ismilyaev, oscd.community, Florian Roth (Nextron Systems), id b120b587-a4c2-4b94-875d-99c9807d6955):
```yaml
detection:
    selection1:
        Image: '/usr/bin/security'
        CommandLine|contains:
            - 'find-certificate'
            - ' export '
    selection2:
        CommandLine|contains:
            - ' dump-keychain '
            - ' login-keychain '
    condition: 1 of selection*
```

Sigma의 한계: 규칙이 **프로세스 생성 로그의 CommandLine 필드**를 전제한다. 정적 파일에 쓰려면 `contains`/`startswith`/`endswith`를 정규식으로 변환해야 한다(SkillGate `sigma_importer.py`가 그 예: `(?=.*a)(?=.*b).*` lookahead 조합). 변환 규칙은 우리가 직접 짜되, 원 규칙 id·author를 결과에 남긴다.

라이선스 판정: DRL 1.1 → 복사·수정 가능. 조건 세 가지(author, 링크, DRL 고지) + 매치 메시지에 author 유지.

---

## 6. 기타 오픈 스캐너

### 6.1 NVIDIA/SkillSpector
- https://github.com/NVIDIA/SkillSpector (SPDX Apache-2.0, LICENSE 원문 "Apache License Version 2.0", star 18,206, push 2026-09-24). 각 소스 파일 헤더 `SPDX-License-Identifier: Apache-2.0`.
- 규칙 위치: `src/skillspector/nodes/analyzers/static_patterns_*.py` 15개 파일. 형식은 Python 리스트의 `(regex, confidence)` 튜플. `static_patterns_data_exfiltration.py`는 "USES_PYTHON_AST = True"로 정규식 + Python `ast` 병용. YARA는 `src/skillspector/yara_rules/{agent_skills,cryptominers,hacktools,webshells}.yar` (rule 수 5+4+5+6 = 20) + `malware.yar.b64`(base64로 인코딩된 파일, 출처 미확인 → 쓰지 않는다).
- README: "71 vulnerability patterns across 17 categories" (여기서 pattern = 규칙 ID, 예 P1, E1, SC2). 정규식 튜플 수는 파일별 `^\s*\(\s*r"` 세기로 약 603 (agent_snooping 29, anti_refusal 33, data_exfiltration 55, deserialization 6, excessive_agency 57, harmful_content 14, memory_poisoning 51, output_handling 41, privilege_escalation 63, prompt_injection 44, rogue_agent 47, ssrf 7, supply_chain 42, system_prompt_leakage 50, tool_misuse 64).
- 출력: `--format json|markdown|sarif`, `--no-llm`으로 정적 전용.

예시 (verbatim):
`static_patterns_supply_chain.py` SC2:
```python
(r"curl\s+[^|]*\|\s*(?:sudo\s+)?(?:ba)?sh", 0.9),
(r"wget\s+[^|]*\|\s*(?:sudo\s+)?(?:ba)?sh", 0.9),
(r"curl\s+[^&]*-o\s+\S+\s*&&\s*(?:sudo\s+)?(?:ba)?sh", 0.8),
```
SC3:
```python
SC3_CODE_PATTERNS = [
    (r"exec\s*\(\s*(?:base64\.)?b64decode\s*\(", 0.95),
    (r"eval\s*\(\s*(?:base64\.)?b64decode\s*\(", 0.95),
    (r"exec\s*\(\s*compile\s*\([^)]*base64", 0.9),
    (r"eval\s*\(\s*atob\s*\(", 0.9),
```
`static_patterns_privilege_escalation.py` PE3:
```python
(r"~?/?\.ssh/(?:id_rsa|id_ed25519|id_ecdsa|id_dsa|authorized_keys|known_hosts)", 0.9),
(r"~?/?\.aws/credentials", 0.9),
(r"(?<!\w)\.env(?:\.local|\.production|\.development)?(?:\s|$|['\"])", 0.6),
(r"(?:keychain|keyring|gnome-keyring)", 0.7),
```
`static_patterns_prompt_injection.py` P1:
```python
(r"ignore\s+(?:all\s+)?previous\s+instructions?", 0.8),
(r"override\s+(?:safety|security|system)", 0.9),
```
`yara_rules/agent_skills.yar` (webhook 유출; 세 그룹 동시 매치 조건):
```yara
        $collector_discord = "discord.com/api/webhooks" nocase
        $collector_telegram = "api.telegram.org/bot" nocase
        $collector_slack = "hooks.slack.com/services" nocase
        $collector_webhook_site = "webhook.site" nocase
    condition:
        any of ($secret_*) and any of ($send_*) and any of ($collector_*)
```
라이선스 판정: Apache-2.0 → 복사 가능(고지 유지). `malware.yar.b64`는 제외.

### 6.2 jason-allen-oneal/openclaw-skill-scanner
- https://github.com/jason-allen-oneal/openclaw-skill-scanner (GitHub API license `null` = 라이선스 파일 없음, star 12)
- 자체 규칙 없음. `scripts/scan_and_add_skill.sh`가 `uv run skill-scanner scan "$SRC_DIR" --format markdown --detailed`로 Cisco 스캐너를 호출하는 래퍼다.
- 판정: 라이선스 없음 → 재사용 불가. 규칙도 없으므로 손실 없음.

### 6.3 Jibberdaffle12/openclaw-skillscan
- https://github.com/Jibberdaffle12/openclaw-skillscan (SPDX MIT, star 1). 파일 하나 `skill_scan.sh` 351줄.
- 형식: bash 배열에 고정 문자열, `grep -F`로 검색. `BLOCKER_PATTERNS_FIXED` 21개 ("eval(", "exec(", "Function(", "subprocess.call", "rm -rf", "atob(", "b64decode", "Buffer.from", "ssh-keygen", "id_rsa", "authorized_keys", "SOUL.md", "MEMORY.md", ...), `WARNING_PATTERNS_FIXED` 11개, `DOC_BLOCKER_PATTERNS` 7개 ("curl | bash", "curl |bash", "wget | sh", "curl -sSL", "powershell -encodedcommand", "Invoke-Expression", "iex("), `DOC_WARNING_PATTERNS` 2개 ("eval $(", "base64 -d").
- 특징: SKILL.md에 선언된 도메인과 코드의 URL 도메인을 대조하는 "undeclared domain" 검사가 있다(가족 (d)에 아이디어로 유용).
- 판정: MIT. 규칙 자체는 정규식도 아닌 고정 문자열이라 가져올 가치가 낮다. "선언 도메인 vs 실제 URL" 아이디어만 참고.

### 6.4 anikrahman0/security-skill-scanner
- https://github.com/anikrahman0/security-skill-scanner (SPDX MIT, star 1, push 2026-02-16). `scanner.js` 520줄, JS 정규식 배열. 카테고리 11개(CRITICAL 4, HIGH 3, MEDIUM 3, LOW 1).
- 예시 (verbatim):
```js
/\.ssh\/|\.aws\/|\.config\//gi,
/\/etc\/passwd|\/etc\/shadow/gi,
/https?:\/\/[a-z0-9-]+\.(xyz|tk|ml|ga|cf|gq)/gi, // Suspicious TLDs
/Buffer\.from\(.*?['"]base64['"]\)/gi,
```
- 판정: MIT. 품질 낮음(`/\$\{.*?\}/g`처럼 모든 템플릿 문자열을 CRITICAL로 잡음, 도메인 화이트리스트 하드코딩). 참고용.

---

## 7. AST 도구

### 7.1 bashlex
- PyPI: https://pypi.org/project/bashlex/ 최신 0.18, 업로드 2023-01-18. `requires_python: >=2.7, !=3.0..3.4`. classifier "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)". 저장소 https://github.com/idank/bashlex SPDX GPL-3.0, 마지막 push 2024-04-08, open issues 38.
- 실제 테스트 (Python 3.13.5, 로컬):
  - `curl ... | sh`, `wget ... | bash` 파이프라인은 잡힘 (`part.kind == 'pipeline'`, `parts[0].word`).
  - `f() { local x=1; [[ $x == 1 ]] && echo y; }` → `ParsingError: unexpected token '$x'` (**`[[ ]]` 미지원**)
  - `echo $(( 1 + 2 ))` → `NotImplementedError: arithmetic expansion`
- 판정: **GPL-3.0이라 MIT 프로젝트에 import 불가**(라이브러리 링크도 파생물). 게다가 2년 반 이상 릴리스 없음, 흔한 bash 문법에서 실패. 탈락.

### 7.2 tree-sitter
- py-tree-sitter: PyPI `tree-sitter` 0.26.0 (2026-06-30), `requires_python >=3.10`, classifier "License :: OSI Approved :: MIT License", 저장소 https://github.com/tree-sitter/py-tree-sitter LICENSE "The MIT License (MIT) / Copyright (c) 2019 Max Brunsfeld, GitHub". 설치 후 `LANGUAGE_VERSION 15, MIN_COMPATIBLE_LANGUAGE_VERSION 13`.
- tree-sitter-bash: PyPI 0.25.1 (2025-12-02), MIT, >=3.10. https://github.com/tree-sitter/tree-sitter-bash (MIT, push 2026-09-13)
- tree-sitter-python: PyPI 0.25.0 (2025-09-11), MIT, >=3.10. https://github.com/tree-sitter/tree-sitter-python (MIT, push 2026-09-13)
- API (0.25+): `Language(tsbash.language())`, `Parser(lang)`, `Query(lang, s)`, `QueryCursor(query).matches(node)` → `[(pattern_index, {capture_name: [Node]})]`. 예전 `language.query()`/`query.matches()` 직접 호출은 0.25에서 제거되었으므로 블로그 예제를 그대로 쓰면 안 된다.
- 로컬 테스트: `bash <(curl -s URL)`도 `(command name: (command_name) argument: (process_substitution (command ...)))`로 파싱되고, `[[ $x == 1 ]]`(test_command), `$(( 1+2 ))`(arithmetic_expansion) 모두 파싱된다.

### 7.3 Python stdlib ast
- PSF 라이선스, 추가 의존성 없음. `ast.parse` → `ast.walk`로 `ast.Call` 순회. Python 3.9+ `ast.unparse`로 스니펫 복원.

### 7.4 권장 경로와 예제 (둘 다 로컬에서 실행해 출력 확인함)

**셸: tree-sitter + tree-sitter-bash** (파이프라인 노드에서 첫 명령이 curl/wget이고 마지막이 sh/bash인 경우)
```python
import tree_sitter_bash as tsbash
from tree_sitter import Language, Parser, Query, QueryCursor
BASH = Language(tsbash.language())
src = open("install.sh", "rb").read()
tree = Parser(BASH).parse(src)
q = Query(BASH, '(pipeline (command name: (command_name) @dl) (command name: (command_name) @sh)'
                ' (#match? @dl "^(curl|wget)$") (#match? @sh "^(ba|z)?sh$"))')
for _, caps in QueryCursor(q).matches(tree.root_node):
    n = caps["dl"][0].parent.parent          # command_name -> command -> pipeline
    print("line", n.start_point[0] + 1, ":", src[n.start_byte:n.end_byte].decode())
```
출력 (테스트 입력): `line 1 : curl -fsSL https://x.io/i.sh | sh` / `line 2 : wget -qO- https://x.io/a | bash -s -- --yes`. `echo hi | grep h`는 잡히지 않는다. `bash <(curl ...)`는 이 쿼리로는 안 잡히므로 `(command name: (command_name) @sh argument: (process_substitution (command name: (command_name) @dl)))` 쿼리를 하나 더 둔다.

**Python: stdlib ast** (`eval`/`exec` 호출의 인자 트리 안에 `b64decode` 호출이 있는 경우)
```python
import ast
def calls(n): return [c for c in ast.walk(n) if isinstance(c, ast.Call)]
def fname(c):
    f = c.func
    return f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else None)
src = open("helper.py").read()
for c in calls(ast.parse(src)):
    if fname(c) in {"eval", "exec"} and any(fname(i) == "b64decode" for i in calls(c)):
        print("line", c.lineno, ast.unparse(c))
```
출력 (테스트 입력): `line 2 exec(base64.b64decode('aW1wb3J0IG9z'))`, `line 3 eval(compile(base64.b64decode(x), 's', 'exec'))`. `print(base64.b64decode("aGk="))`는 잡히지 않는다. 정규식 `exec\s*\(\s*base64\.b64decode` (SkillSpector SC3)로는 3번째 줄(compile 경유)을 놓친다. 이것이 AST를 쓰는 이유다.

권장 이유: (1) 둘 다 MIT/PSF, (2) 활발히 유지보수됨, (3) Python 3.10+ 요구는 우리 환경(3.13)과 맞음, (4) SKILL.md 안의 ```` ```bash ```` 코드 펜스도 같은 파서로 처리 가능. tree-sitter-python 대신 stdlib `ast`를 택한 이유는 의존성 0, 그리고 Python 2 문법이나 구문 오류 파일은 어차피 stage 2로 넘길 것이기 때문이다(구문 오류 시 `SyntaxError`를 잡아 "parse_failed" 플래그를 남기고 정규식 결과만 쓴다).

---

## 8. 다섯 가족 → 규칙 소스 매핑

| 가족 | 1차 소스 (복사) | 보강 | 비고 |
|---|---|---|---|
| (a) curl \| sh / wget \| bash | SkillGate RCE001~RCE004 (MIT); SkillSpector SC2 6건 (Apache) | Sigma `proc_creation_lnx_susp_pipe_shell`, `proc_creation_lnx_curl_wget_exec_tmp` (DRL) | tree-sitter 파이프라인 쿼리가 정규식 우회(`curl ... \| sudo bash -s`, 프로세스 치환) 커버 |
| (b) base64 + eval/exec | SkillGate RCE010~012, EVAS009, OBFUS008 (MIT); SkillSpector SC3 (Apache); Cisco YARA `$obfuscated_exec` (Apache) | Sigma `proc_creation_lnx_base64_execution`, `proc_creation_lnx_python_base64_encoded_execution` (DRL) | Python은 stdlib ast로 `exec(<...b64decode...>)` 구조 매칭 |
| (c) 자격증명 경로 | SkillGate CRED001~CRED019 (`.ssh/id_*`, `.aws/credentials`, `.env`, `Library/Keychains/`) (MIT); SkillSpector PE3 (Apache); Cisco YARA `$credential_file_access` (Apache) | 리터럴 토큰은 gitleaks 222 규칙 (MIT); Sigma `proc_creation_macos_creds_from_keychain` (`security dump-keychain`) (DRL) | Sigma에는 경로 규칙이 거의 없음 |
| (d) 외부 유출 (POST/webhook/DNS) | SkillGate EXFIL001~006, EXFIL100~109, EXFIL120 (curl -d/-F/--upload-file, wget --post-file, nc, `dig $(...)`, base64\|nslookup) (MIT); SkillSpector E1 + `agent_skills.yar` webhook 3중 조건 (Apache); Cisco DATA_EXFIL_HTTP_POST, DATA_EXFIL_SOCKET_CONNECT (Apache); ATR-2026-00162/00201 (MIT) | Sigma `proc_creation_lnx_susp_curl_fileupload` (DRL); Jibberdaffle의 "SKILL.md 선언 도메인 vs 코드 URL 대조" 아이디어 (MIT) | Cisco DATA_EXFIL_HTTP_POST는 `attacker\|evil\|webhook...` 키워드 의존이라 recall 낮음. SkillSpector `any of ($secret_*) and any of ($send_*) and any of ($collector_*)` 방식이 낫다 |
| (e) 원격 지시문 로딩 + 지시문 오버라이드 텍스트 | Cisco PROMPT_INJECTION_* 5 rules/17 regex (`file_types: [markdown]`) (Apache); Cisco ATR 팩 `atr_prompt_injection.yaml` 242 rules/1,038 regex (MIT, 원본 ATR-2026-00001 등); SkillSpector P1/P2/P3/AR1~3 (Apache); SkillGate `rules/skills.yaml` 10건 + INJ006/007 (MIT) | Cisco YARA `indirect_prompt_injection_generic`, `coercive_injection_generic`; SkillSpector `agent_skill_remote_bootstrap_execution` (`exec(requests.get(...).text)`) | "fetch URL then treat as instructions"는 순수 정규식으로는 약하다. Cisco `check_active_remote_execution()`처럼 "원격 취득 + 실행/지시"의 결합 조건으로 만들고, 애매한 것은 stage 2로 넘긴다 |

---

## 9. 라이선스 실무 체크리스트 (우리 저장소에 넣을 때)

1. `rules/` 아래에 출처별 하위 폴더를 두고 각 폴더에 원 LICENSE 사본을 넣는다: `rules/skillgate/LICENSE`(MIT), `rules/cisco/LICENSE`(Apache-2.0), `rules/atr/LICENSE`(MIT), `rules/gitleaks/LICENSE`(MIT), `rules/sigma/LICENSE.Detection.Rules.md`(DRL 1.1), `rules/skillspector/LICENSE`(Apache-2.0).
2. 규칙을 우리 YAML로 변환하더라도 각 규칙에 `source: {repo, path, rule_id, author, license}` 필드를 남긴다. DRL 1.1은 탐지 메시지에도 author를 요구하므로 finding 출력에 `source.author`를 포함한다.
3. Apache-2.0 파일을 수정하면 파일 상단에 "Modified by <팀> on <날짜>" 한 줄을 넣는다(4(b)).
4. 저장소 루트 `NOTICE` 또는 `THIRD_PARTY_LICENSES.md`에 위 목록을 적는다.
5. trufflehog, bashlex는 저장소에 어떤 형태로도 넣지 않는다. jason-allen-oneal 저장소는 라이선스가 없으므로 인용만 한다.
6. SkillSpector `malware.yar.b64`는 출처가 파일 안에 없으므로 쓰지 않는다.

---

## 10. 조사 중 발견한 unknown (팀 확인 필요)

- SkillGate 저장소 규칙 수(533)와 논문 수치(530)가 다르다. 어느 쪽을 인용할지 결정 필요. 제안: 둘 다 병기.
- Cisco README의 규칙 수는 pack.yaml 기준 189(core)이고, ATR 712를 합치면 900이 넘는다. 발표에서 "Cisco 스캐너 규칙 N개"라고 말할 때 어느 팩까지 포함하는지 명시해야 한다.
- ATR upstream은 README에서 "777 live rules" 중 stable 106이라 하고, git tree에는 YAML 825개가 있다(deprecated 포함 추정). 인용 시 "2026-09-24 main 기준 rules/ 아래 YAML 825개, README 표기 777 live"로.
- Cisco는 JSON Schema 파일을 제공하지 않는다. 베이스라인 비교 스크립트는 `models.py`의 `Finding.to_dict()` 키에 맞춰 작성하되, 버전 고정(`pip install cisco-ai-skill-scanner==<버전>`)이 필요하다. 버전은 설치 시점에 확인.
- py-tree-sitter 0.26.0은 PyPI 메타데이터의 `license` 필드가 비어 있고 classifier로만 MIT가 표시된다. 저장소 LICENSE로 확인했으므로 문제없지만 인용 시 저장소 LICENSE URL을 쓴다.

## 11. 재현용 명령 (직접 센 방법)

```
gh api repos/gitleaks/gitleaks/contents/config/gitleaks.toml --jq .content | base64 -d | grep -c '^\[\[rules\]\]'      # 222
gh api "repos/awsm-research/skillgate/git/trees/main?recursive=1" --jq '.tree[].path'                                   # 파일 목록
python -c "import ast;m=ast.parse(open('attack_patterns.py').read());print([len(n.value.elts) for n in m.body if isinstance(n,(ast.Assign,ast.AnnAssign)) and getattr(n.targets[0] if isinstance(n,ast.Assign) else n.target,'id','')=='ATTACK_PATTERNS'])"   # [428]
gh api repos/SigmaHQ/sigma/git/trees/HEAD?recursive=1 --jq '.tree[].path' | grep -c '^rules/.*\.yml$'                   # 3144
gh api repos/trufflesecurity/trufflehog/contents/pkg/detectors --jq '[.[]|select(.type=="dir")]|length'                  # 886
pip install --target pylib tree-sitter==0.26.0 tree-sitter-bash tree-sitter-python bashlex ; python ts_bash_demo.py ; python bashlex_demo.py
```
