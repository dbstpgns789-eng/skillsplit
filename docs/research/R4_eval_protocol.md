> **정정 (2026-09-26):** 이 보고서의 "MaliciousSkillBench에는 범주별 재현율이 없다"는 판정은 틀렸다. 논문 부록 J.4(Figure 6)가 스캐너 3종의 공격 범주별 재현율을 보고한다(SkillFortify Credential Access 81.5% 등). 부록 J 전문은 `wiki/sources.md`에 정리. "roughly 21 MB input"(J.3, Table 47)도 확인됨.

# R4. 평가 프로토콜 비교 조사: 공개 벤치마크와 우리 결과를 나란히 놓기 위한 규약

작성일 2026-09-25. 조사 범위: MaliciousSkillBench, MalSkillBench, SkillGate/SkillsBench-1650, SkillVetBench(+companion). 영어 원문은 그대로 인용하고(따옴표 안은 원문 그대로), 수치는 원문 또는 저장소 파일에서 직접 확인한 것만 적는다. 저장소 파일은 `gh api repos/<o>/<r>/contents/<path>`로, 논문은 arXiv HTML을 내려받아 확인했다. 내가 직접 계산한 수치는 `[계산]`으로 표시한다.

---

## 0. 한 줄 결론

- **평가 단위는 skill(패키지)**이다. MaliciousSkillBench와 MalSkillBench는 skill 단위, SkillGate만 file 단위(`n=1,650 files`)다. SkillsBench-1650은 1행 = 1 skill(SKILL.md + 동봉 스크립트 연결)이라 file 단위와 skill 단위가 사실상 같다.
- **Source-Disjoint 테스트셋(1,384 = 839 malicious / 545 benign)**이 우리가 기존 스캐너 수치(Cisco, SkillFortify, SkillSpector, Word-SVM) 옆에 놓을 수 있는 유일한 공개 표다. 다만 이 테스트셋의 "wild" malicious는 **7개뿐**이라(benign wild는 446) 실세계 vs 합성 분리는 전체 9,740 위에서 따로 해야 한다.
- **공격 카테고리별 recall은 MaliciousSkillBench 논문에 없다.** 있는 것은 MalSkillBench(B1~B15 행동별, CI/PI/MIXED 벡터별, wild 4개 행동별)와 SkillVetBench companion(7개 카테고리별 verdict 수)뿐이다.
- **라이선스**: MaliciousSkillBench의 메타데이터·분할·택소노미는 CC BY 4.0이라 우리가 만든 라벨·스크립트를 공개해도 된다. **skill 본문 재배포는 하지 말고 `benchmark_id`로만 가리킨다.** 특히 SRC001(MalSkillBench)은 "academic-research-only", SRC010(SkillTrustBench)은 CC-BY-NC-SA-4.0이다. MalSkillBench 원본 저장소는 LICENSE 파일이 없고 README에 "For academic research use only."만 있다.

---

## 1. MaliciousSkillBench (arXiv 2608.19901, repo protectskills/MaliciousSkillBench)

출처
- 논문 HTML: https://arxiv.org/html/2608.19901v1
- 저장소: https://github.com/protectskills/MaliciousSkillBench
- HF: https://huggingface.co/datasets/ProtectSkills/MaliciousSkillBench (gated: false, cardData.license: cc-by-4.0, lastModified 2026-08-22)

### 1(a) Source-Disjoint 프로토콜의 정의 (원문)

논문 6.1 Evaluation Design:
> "All evaluations use the frozen 9,740-unit master table (7,505 malicious / 2,235 benign). Random is label-stratified 70/10/20; Malicious-Structural-Disjoint keeps each of the 4,588 malicious structural families atomic across partitions; and Source-Disjoint holds out SRC009, SRC011, and SRC012 after removing eight identities whose provenance crosses held-out and non-held-out sources."

Appendix F.2 (Source-Disjoint):
> "SRC009, SRC011, and SRC012 are held out entirely for testing. After the eight cross-boundary multi-source normalized identities are removed, all remaining records associated with these held-out sources enter the test side and non-held-out sources supply train/validation. The 1,384-unit test therefore remains identical to the held-out-source composition used for the longitudinal pre-recovery/post-recovery comparison, while the non-held-out train/validation pool expands after artifact recovery."

Appendix F.3 (왜 "source-conditioned"라고 부르는가):
> "Source-Disjoint is intentionally reported as source-conditioned generalization, because source identity is entangled with label prevalence and corpus construction. Table 27 makes this confounding visible. SRC009 contributes only malicious test units, SRC011 is overwhelmingly benign, and SRC012 is balanced. The aggregate test set is 839 malicious / 545 benign, but that aggregate ratio hides substantial between-source label skew."

Table 27 (held-out 구성, 원문 수치):

| ID | Source | Malicious | Benign | Total | Malicious share |
|---|---|---:|---:|---:|---:|
| SRC009 | SkillHarm | 728 | 0 | 728 | 100.0% |
| SRC011 | ATR Skill Security | 21 | 455 | 476 | 4.4% |
| SRC012 | SkillFortifyBench | 90 | 90 | 180 | 50.0% |
| Total | – | 839 | 545 | 1,384 | 60.6% |

> "This composition is why we do not interpret the Source-Disjoint gap as a pure causal effect of 'unseen source identity.' Holding out a source simultaneously changes provenance, construction procedure, documentation style, and label mixture."

**왜 그 세 소스인가**: 논문과 저장소 문서 어디에도 SRC009/011/012를 고른 이유는 명시되어 있지 않다(HTML 전문을 grep해서 확인). 저장소 `benchmark/protocols.md`도 같은 사실만 반복한다:
> "**Source-Disjoint.** Training sources and evaluation sources are disjoint. Held-out sources are `SRC009`, `SRC011`, and `SRC012`. The test set contains 839 malicious and 545 benign identities. Results from this protocol describe **source-conditioned shift**. They should not be reported as universal unseen-source or out-of-distribution generalization."
(https://github.com/protectskills/MaliciousSkillBench/blob/main/benchmark/protocols.md)

Appendix F.6 (해석 경계):
> "Third, Source-Disjoint measures source-conditioned distribution shift under the frozen source partition; it does not isolate a causal estimate of universal unseen-source difficulty. In particular, the 321 cross-partition structural families under Source-Disjoint are expected and do not contradict source disjointness."

분할 매니페스트 실제 값 `[계산]` (`metadata/splits/source_disjoint.csv`, 9,740행):

| split | benign(0) | malicious(1) |
|---|---:|---:|
| train | 1,521 | 5,992 |
| validation | 169 | 666 |
| test | 545 | 839 |
| excluded | 0 | 8 (전부 SRC001) |

### 1(b) 다른 분할

`benchmark/protocols.md` 원문:
> "**Random.** A conventional i.i.d.-style partition of the 9,740 identities. Near-duplicate Skills from the same structural family may appear in more than one split."
> "**Source-Balanced Random.** A random partition that balances source composition more evenly across splits. It remains a random partition rather than a disjointness protocol."
> "**Malicious-Structural-Disjoint.** Malicious structural families are not shared across train/validation/test. This reduces evaluation leakage from near-duplicate malicious Skills. It is not a claim that all possible structural reuse has been removed."

논문 F.2 추가 원문:
> "Random. We perform a label-stratified 70/10/20 assignment over the normalized-unique master table. Exact and normalized identity are disjoint across partitions, but source, structural-family, and explicit-lineage relationships are not constrained."
> "Malicious-Structural-Disjoint. Each of the 4,588 frozen malicious operational structural families is treated as an atomic group: a family may appear in train, validation, or test, but never in more than one partition. Benign structural clustering is not part of the frozen malicious-family pipeline; each benign normalized-unique unit therefore uses a singleton fallback grouping ID."

structural family 계산법 (논문 4.3):
> "On one representative per normalized malicious identity, a frozen static-similarity pipeline at threshold 0.68 yields 4,588 operational structural families."

분할 크기 (Table 26 / protocols.md):

| Protocol | File | Train | Validation | Test |
|---|---|---:|---:|---:|
| Random | `random.csv` | 6,818 (5,254/1,564) | 974 (750/224) | 1,948 (1,501/447) |
| Source-Balanced Random | `source_balanced_random.csv` | 6,817 | 973 | 1,950 (1,501/449) |
| Malicious-Structural-Disjoint | `m_structural_disjoint.csv` | 6,818 | 974 | 1,948 (1,501/447) |
| Source-Disjoint | `source_disjoint.csv` | 7,513 (5,992/1,521) | 835 (666/169) | 1,384 (839/545) + 8 excluded |

F.1: "Seed 42 is used for the frozen assignments." 분할은 `structural_family_id` 컬럼(benign은 null)과 `*_split` 컬럼으로 `metadata/benchmark_manifest.csv`에 들어 있다. 문서 지시: "Use the frozen split manifests in `metadata/splits/`. Do not regenerate partitions."

### 1(c) 보고 지표와 임계값

논문 6.1:
> "Learned baselines use only inert primary Skill instruction text: word TF–IDF with logistic regression or linear SVM, and character char_wb TF–IDF with linear SVM. We report Macro-F1, malicious recall, and benign FPR_B."
> "The same primary-artifact representation is scanned by three public tools with pre-registered gates: Cisco-local-behavioral (local HIGH/CRITICAL gate), SkillFortify-offline (MEDIUM+), and SkillSpector-static (LLM disabled; native block gate)."
> "Because learned models are protocol-trained and scanners use fixed external configurations, this is an operational comparison that does not isolate model capacity."

Appendix G.4 / Table 31 (정의):
> "Macro-F1 | (F1_M + F1_B)/2 | Primary paper-level metric; gives equal weight to malicious and benign classes."
> "Benign FPR | FP/(FP+TN) | Fraction of truly benign Skills incorrectly flagged malicious; central transfer error diagnostic."
> "AUROC / AUPRC | ranking metrics over continuous decision scores | Secondary diagnostics; omitted for constant predictors without a decision score."
> "We do not calibrate probabilities or tune a decision threshold on the validation partition for the primary comparisons."

Appendix I (AUROC/AUPRC 언급):
> "Random AUROC is 0.965–0.986 for the three text models, whereas Source-Disjoint AUROC is 0.738–0.821. AUPRC also decreases, although it remains numerically high because malicious is the positive class and remains prevalent in the held-out test. We therefore keep Macro-F1, malicious recall, and benign FPR as the paper-facing summaries, while AUROC/AUPRC remain supplementary ranking metrics."

주의: AUPRC 정확한 값은 본문에 없고 "numerically high"라고만 한다. 우리 PR-AUC를 이 논문 값 옆에 놓을 수는 없다.

저장소 `evaluation/metrics.py`는 `macro_f1`, `malicious_recall`, `benign_fpr`, `accuracy`만 구현(라벨 1=malicious, 0=benign). 학습 베이스라인 seed는 "Full paper tables used seeds 42/43/44" (`baselines/README.md`), Table 2 값은 "three-seed mean Macro-F1".

**결과 표 (원문 수치)**

Table 2 (Macro-F1, 학습 베이스라인):

| Model | Random | Source-Balanced | M-Struct. | Source-Disjoint | Rand. FPR_B | Source FPR_B |
|---|---:|---:|---:|---:|---:|---:|
| Word TF–IDF + LR | .882 | .874 | .860 | .661 | .105 | .620 |
| Word TF–IDF + SVM | .932 | .921 | .916 | .665 | .094 | .624 |
| Char TF–IDF + SVM | .921 | .907 | .883 | .653 | .098 | .644 |

Table 3 / `scanner_eval/source_disjoint_results.csv` (Source-Disjoint test 1,384):

| method | macro_f1 | malicious_recall | benign_fpr |
|---|---:|---:|---:|
| Cisco-local-behavioral | 0.308 | 0.025 | 0.011 |
| SkillFortify-offline | 0.349 | 0.253 | 0.499 |
| SkillSpector-static | 0.281 | 0.000 | 0.0055 |
| Word-SVM | 0.665 | 0.956 | 0.624 |

본문 6.3/6.4 세부 수치:
> "The word-SVM flags 340/545 benign Skills while missing only 37/839 malicious Skills; SRC011 contributes 293 false positives."
> "Balancing lowers word-SVM Source-Disjoint benign FPR from 62.4% to 43.3% and raises Macro-F1 from 0.665 to 0.710"
> "On SRC011's 455 benign Skills, the word-SVM produces 293 false positives, SkillFortify 272, Cisco 6, and SkillSpector 3."
> "SkillFortify also benefits from the related SRC012/SkillFortifyBench source: excluding SRC012 lowers its Source-Disjoint Macro-F1 from 0.349 to 0.254 and worsens both recall and FPR."

`scanner_eval/README.md` 주의문: "SkillSpector-static is a static / no-LLM configuration. It is not the LLM-backed SkillSpector configuration used in some external work." / "Cisco-local-behavioral was run in a local compatibility environment".

### 1(d) 공격 택소노미 (11 attack + 9 derived impact)

`benchmark/taxonomy.md` (https://github.com/protectskills/MaliciousSkillBench/blob/main/benchmark/taxonomy.md):
> "Attack mapping coverage is **4,983 / 7,505** malicious identities (66.4%). The remaining malicious identities are unmapped rather than labeled as 'no attack.' Mappings are multi-label."

11 attack categories (stable code / display name) + Table 24 원문 수치 (identities, % mapped, sources):

| `attack_category_codes` | `attack_categories` | Identities | % mapped | Sources |
|---|---|---:|---:|---:|
| `execution_code_delivery` | Execution / Code Delivery | 3,320 | 66.6 | 7 |
| `instruction_goal_memory_manipulation` | Instruction / Goal / Memory Manipulation | 1,671 | 33.5 | 8 |
| `privilege_tool_authority_abuse` | Privilege / Tool / Authority Abuse | 1,013 | 20.3 | 6 |
| `data_exfiltration_disclosure` | Data Exfiltration / Disclosure | 355 | 7.1 | 6 |
| `resource_availability_abuse` | Resource / Availability Abuse | 330 | 6.6 | 4 |
| `credential_access` | Credential Access | 303 | 6.1 | 5 |
| `persistence_control` | Persistence / Control | 249 | 5.0 | 6 |
| `dependency_supply_chain` | Dependency / Supply-Chain Abuse | 167 | 3.4 | 5 |
| `integrity_output_manipulation` | Integrity / Output Manipulation | 97 | 1.9 | 3 |
| `defense_evasion_obfuscation` | Defense Evasion / Obfuscation | 34 | 0.7 | 3 |
| `discovery_reconnaissance` | Discovery / Reconnaissance | 15 | 0.3 | 2 |

`[계산]` `metadata/benchmark_manifest.csv`의 `attack_categories` 세미콜론 분리 카운트도 위 표와 일치한다 (3320/1671/1013/355/330/303/249/167/97/34/15).

**카테고리별 정의문은 저장소 문서에도 논문에도 없다.** 있는 것은 이름·코드·카운트뿐이다. 매핑 방식(Appendix E.1): 소스 원래 라벨을 결정적으로 매핑했고, SRC001은 "We recover these labels only by exact suffix matching, never by Skill-text interpretation. This yields vector and behavior labels for 1,466 identities and insertion-strategy labels for 166; 1,960 SRC001 identities have no trustworthy row-level taxonomy". Table 25 설명: "Labels are multi-label and come from documented source-native behavior semantics, not model labeling."

Derived impact (9개, `impact_category_codes`) + Table 25 카운트 `[계산 일치]`: `unauthorized_code_execution_system_control` 489, `sensitive_data_disclosure` 423, `credential_compromise` 297, `agent_control_instruction_compromise` 275, `privilege_control_manipulation` 247, `resource_service_abuse` 212, `persistence_sustained_control` 146, `availability_destructive_impact` 144, `integrity_output_manipulation` 99. taxonomy.md: "These are **derived harmonized impacts**. They are not source-provided annotations and must not be treated as ground truth."

MalSkillBench 유래 CI/PI/MIXED는 SRC001에만 붙어 있다 (E.4): "CI 621 (42.4%), PI 484 (33.0%), and MIXED 361 (24.6%). These labels remain SRC001-specific".

### 1(e) 검출기의 카테고리별 recall이 있는가

**없다.** Section 6은 집계 Macro-F1/recall/FPR만 보고한다. Appendix E.3의 Figure 3은 "Provenance composition by harmonized attack category"(카테고리별 provenance 구성)이지 검출 성능이 아니다. 소스별로는 SRC011 benign에 대한 FP 수(위 6.4 인용)만 있다. L.4 Intended uses에 "threat-stratified analysis"가 명시되어 있으므로 우리가 카테고리별 recall을 내는 것은 벤치마크 의도 안에 있다.

Source-Disjoint test에서 카테고리별 분석 가능 규모 `[계산]`: 839 malicious 중 attack 매핑된 것은 237. `instruction_goal_memory_manipulation` 75, `resource_availability_abuse` 62, `data_exfiltration_disclosure` 52, `privilege_tool_authority_abuse` 27, `dependency_supply_chain` 8, `execution_code_delivery` 7, `credential_access` 4, `persistence_control` 1, `defense_evasion_obfuscation` 1. 즉 SD test만으로는 카테고리별 recall이 소표본이고, 전체 9,740(4,983 mapped)에서 해야 의미가 있다.

### 1(f) `provenance`와 `evidence_type`

`benchmark/schema.md`: `provenance` "Frozen provenance category." / `evidence_type` "Frozen evidence type when available." (schema.json도 같은 한 줄뿐). 정의는 논문 Table 9, Table 10에 있다.

Table 9 (Provenance vocabulary):
> "wild | Collected from a real upstream ecosystem/repository under the source's published semantics; no benchmark-authored attack construction."
> "synthetic | Synthetic standalone Skill/test artifact generated or authored for evaluation."
> "injected | Malicious/harmful content is inserted into a pre-existing carrier, host Skill, or task construction."
> "backdoored | Benign-looking Skill contains hidden or triggered malicious behavior."
> "test_fixture | Curated or benchmark-authored fixture used as a controlled security test artifact."
> "mixed_unresolved | Source reports a mixture of origins but lacks a trustworthy row-level provenance mapping."

Table 10 (Evidence level):
> "human+runtime | Human-grounded label together with runtime/behavioral confirmation."
> "runtime | Behavioral execution/runtime evidence without the combined human+runtime designation."
> "static | Static artifact inspection or curated source evidence without runtime confirmation."
> "scanner | Automated scanner or security-signal output."
> "constructed | Label is known from controlled benchmark construction, injection, or backdoor generation."
> "Scanner-only evidence therefore never enters Core malicious ground truth."

매니페스트 실제 분포 `[계산]` (9,740행):

| provenance | benign | malicious | 비고 |
|---|---:|---:|---|
| wild | 1,936 | 229 | benign wild는 SRC010 1,490 + SRC011 446; malicious wild는 SRC002 153, SRC004 33, SRC005 30, SRC010 6, SRC011 7 |
| injected | 153 | 3,341 | SRC010 2,770, SRC009 570, SRC013 154 |
| mixed_unresolved | 0 | 3,426 | 전부 SRC001(MalSkillBench). 생성/wild 구분이 행 단위로 없음 |
| synthetic | 90 | 250 | SRC012 90/90, SRC010 160 |
| backdoored | 0 | 159 | SRC009 158, SRC008 1 |
| test_fixture | 56 | 100 | SRC006 131, SRC011 23, SRC008 2 |

| evidence_type | benign | malicious |
|---|---:|---:|
| constructed | 254 | 3,764 |
| human+runtime | 0 | 3,612 |
| runtime | 45 | 86 |
| static | 1,936 | 43 |

`[계산]` provenance × evidence_type: wild = static 1,979 + human+runtime 186; injected/backdoored/synthetic = 전부 constructed; mixed_unresolved = 전부 human+runtime.

**Source-Disjoint test(1,384)의 provenance 구성 `[계산]`**:

| provenance | benign | malicious |
|---|---:|---:|
| wild | 446 | 7 |
| injected | 0 | 570 |
| backdoored | 0 | 158 |
| synthetic | 90 | 90 |
| test_fixture | 9 | 14 |

즉 SD test에서 "실세계 malicious"는 7개뿐이다. 실세계 vs 합성 비교는 SD test로는 불가능하고, 전체 9,740 위에서 provenance별로 해야 한다.

### 1(g) 라이선스와 책임 있는 사용

`LICENSE-DATA` 첫 문단 (https://github.com/protectskills/MaliciousSkillBench/blob/main/LICENSE-DATA):
> "MaliciousSkillBench-authored benchmark metadata, derived annotations, taxonomy mappings, split manifests, and related database organization in this repository are licensed under the Creative Commons Attribution 4.0 International License (CC BY 4.0). This license does not relicense third-party Agent Skill artifacts. Those materials retain their respective upstream terms. See THIRD_PARTY_NOTICE.md."

`THIRD_PARTY_NOTICE.md`:
> "Third-party Skill artifacts included or referenced by this project are **not** relicensed under Apache-2.0 or CC BY 4.0. Those artifacts retain their respective upstream terms and attribution requirements."
> "When redistributing or discussing source-specific artifacts, cite the corresponding upstream paper, repository, or dataset record in addition to MaliciousSkillBench."

코드는 Apache-2.0 (`LICENSE`, README).

논문 Appendix L.3 (Licensing and redistribution policy):
> "Each source retains its own upstream license and redistribution constraints. Appendix A.3 records the frozen revision and benchmark-side policy for all 13 sources. The benchmark does not infer redistribution permission from the fact that a repository is publicly accessible, and it does not use a permissive benchmark-level license to supersede a more restrictive source license."

Appendix A.3 Table 6 (소스별 upstream license / 패키지 재배포 정책, 원문):

| ID | Upstream license | Source/package redistribution policy |
|---|---|---|
| SRC001 MalSkillBench | academic-research-only | adapter only |
| SRC002 | MIT | exact frozen static Skill text released; historical snapshot provenance retained |
| SRC003 | MIT | allowed |
| SRC004 | MIT | exact frozen static Skill text released; historical snapshot provenance retained |
| SRC005 | MIT | allowed |
| SRC006 AgentTrap | terms not provided | metadata/hash only |
| SRC007 | MIT | allowed |
| SRC008 | Apache-2.0 snapshot | allowed for acquired repository snapshot |
| SRC009 SkillHarm | CC-BY-4.0 | metadata/hash only |
| SRC010 SkillTrustBench | CC-BY-NC-SA-4.0 | metadata/hash only |
| SRC011 | MIT | allowed |
| SRC012 | MIT | allowed |
| SRC013 | Apache-2.0 | allowed |

(주의: 이 표는 논문 시점 정책이고, 현재 저장소 `packages/`에는 SRC009, SRC010 아카이브도 올라와 있다. 논문 L.5가 "License/redistribution clarification ... May change what is distributed"라고 하므로 이후 갱신된 것으로 보인다. 그래도 upstream 라이선스 자체(SRC010 NC-SA, SRC001 academic-only)는 바뀌지 않는다.)

`RESPONSIBLE_USE.md` 전체 요지 (원문):
> "MaliciousSkillBench is intended for defensive security research and detection evaluation."
> "Use the data in isolated, non-production analysis environments."
> "Do not execute untrusted Skills, follow embedded URLs, or install companion packages from benchmark artifacts."
> "Package-level archives under `packages/`, where present, are untrusted research samples and must not be executed."

L.4 Intended uses:
> "The benchmark can also support development of new defensive models provided that comparisons report the benchmark version, split protocol, detector inputs, and class-aware metrics."

**우리 판단**
- 우리가 만든 라벨(1단계 규칙 hit, 2단계 LLM verdict, 카테고리별 결과), 평가 스크립트, `benchmark_id`별 결과 CSV는 공개 가능. 근거: 우리 산출물은 우리 저작물이고, 결합하는 벤치마크 메타데이터(`benchmark_id`, `label`, `source_id`, `provenance`, split)는 CC BY 4.0. 출처 표기(MaliciousSkillBench + 해당 upstream) 필요.
- skill 본문(`skill_text`)이나 `packages/` 내용물을 우리 저장소에 복사해 올리지 않는다. HF `benchmark_id`로 조인하게 한다. 특히 SRC001(academic-research-only)과 SRC010(CC-BY-NC-SA-4.0) 텍스트는 재배포 불가로 본다.
- 보고서에 skill 본문을 예시로 인용할 때는 짧게, 출처 표기와 함께.
- 학부 과제/연구 목적이므로 SRC001의 academic-research-only 조건은 충족한다.

### 1(h) `packages/` 내용

`packages/README.md` (https://github.com/protectskills/MaliciousSkillBench/blob/main/packages/README.md):
> "This directory contains source-level malicious Agent Skill artifacts corresponding to the 7,505 malicious identities in MaliciousSkillBench."
> "Some source artifacts are naturally multi-file Skill packages, while others are source-native single files. Sensitive credential values are replaced with sanitized placeholders where necessary; such cases are marked in the manifest."
> "The SRC002 archive preserves 157 accepted source artifacts: 153 primary benchmark identities, three cross-source duplicates, and one cross-label-excluded source artifact."
> "Do not execute untrusted Skill package contents."

**스크립트를 포함하는가: 예.** `package_manifest.csv` `[계산]` (7,505행): `artifact_form` = COMPLETE_PACKAGE_BACKED 7,364 / NATIVE_SINGLE_FILE 141. `package_file_count` 소스별 평균: SRC001 1.62 (max 90), SRC002 3.77, SRC004 6.24, SRC005 1.0, SRC006 10.06, SRC008 10, SRC009 6.19, SRC010 7.63 (max 65), SRC011 1.0, SRC012 1.0, SRC013 5.85. `sanitized`=yes 114, `hygiene_filtered`=yes 3 (제거된 파일 예: `scripts/__pycache__/*.pyc`). `release_fidelity`: EXACT_TO_PRESERVED_UNIFIED_SOURCE_ARCHIVE 7,099 / EXACT_TO_PRESERVED_SNAPSHOT 148 / NATIVE_TEXT_ONLY 141 / SANITIZED_NOT_BIT_IDENTICAL 114 / PUBLIC_HYGIENE_FILTERED_NOT_BIT_IDENTICAL 3.

실제 tarball 확인 (SRC008_packages.tar.gz 내부): `packages/00001_ASB04_006168/SKILL.md`, `references/*.md`, `scripts/query_builder.py`, `scripts/result_formatter.py`, `scripts/result_verifier.py`, `scripts/schema_analyzer.py`, `scripts/skills_initialize.py`, `.query_cache/`, `.schema_cache/`. SRC011/SRC012 아카이브는 identity당 단일 `.md` 파일(`artifacts/NNNNN_<id>/SKILL.md` 또는 `claude_mal_A05_004.md`).

**중요**: benign 2,235개는 `packages/`에 없다(malicious만). benign은 HF `primary.parquet`의 `skill_text`(단일 텍스트)뿐이다. 따라서 1단계 정적 규칙이 `scripts/*.py`를 본다면 malicious에는 스크립트가 있고 benign에는 없는 **비대칭**이 생긴다. 공정 비교를 위해 MaliciousSkillBench 평가는 `skill_text`(SKILL.md 텍스트) 단일 입력으로 하고, 패키지 단위 평가는 별도 조건으로 표시해야 한다. 논문도 "Learned baselines and the common scanner track use static primary Skill artifacts and exclude package-level/runtime behavior." (Section 8)

`packages/SHA256SUMS.txt` (원문 그대로):
```
878498b42d9c67d0b084ef416153d69742ef75e57c938d7a38614f9bb914c3db  SRC001_packages.tar.gz
bf2532cb0e7fd3a76a2cf1bbb53cff1cd77fe67b3f152f802c084ef196860ed5  SRC002_packages.tar.gz
206ab5bde4177475ba1d9da3f711197c38e082329b77aee969f99ecbbc385701  SRC004_packages.tar.gz
2ad5fcdacd2f68d73727d4a93e346d081a5bb1ec13a801afbd4d35a2d6d8b473  SRC005_artifacts.tar.gz
b2a8d1f54918bbd9f9b69e869e4914dd7416cf166b3d351a75a55c87f355bc56  SRC006_packages.tar.gz
286026390acdd4cc01f6821c559bbb725893f665393aa43a365598c010608a36  SRC008_packages.tar.gz
10bf2de3d35b50a3c8888356831d43b4963f61f726cab931aeab33ecd60c882f  SRC009_packages.tar.gz
db9e7b65327659ade4c2a6bb0c69c7037a50f9e8ab7509b6441d486bcf7121af  SRC010_packages.tar.gz
db2da0e76041c73826e604453544bc0c3d3c7ce3c90c6db62e3dddcc23f9468a  SRC011_artifacts.tar.gz
b57c3663d9d943802bdb341659ba8e0cd0ffa4befcac407e268f4a8ad9a6398d  SRC012_artifacts.tar.gz
6e6f769319d5f6d0d0add1588690e2fcd12ca9e3d2364d2acf580225cff98230  SRC013_packages.tar.gz
0225ebe52782dae384ca6eb622566021c9c6b309867d65a8f1007d516242096a  package_manifest.csv
2b6144053364ed54177d5112becc372b55a642dc377ef34a408233d71c2a60c1  package_manifest.parquet
b3eb3684e92cd8d71f2acf8d6b0973e7c430a361214f71695455d2b02fd192e3  README.md
```
아카이브 크기(GitHub API): SRC001 18.0 MB, SRC010 31.6 MB, SRC009 8.8 MB, 나머지 2.2 MB 이하. SRC003/SRC007은 auxiliary라 아카이브 없음.

---

## 2. MalSkillBench (arXiv 2606.07131, repo lxyeternal/MalSkillBench)

출처
- 논문 HTML: https://arxiv.org/html/2606.07131
- 저장소: https://github.com/lxyeternal/MalSkillBench (GitHub API `license: null`, updated 2026-09-18)

### 2(a) 평가 프로토콜

논문 4.5 실험 설정 원문:
> "All baselines are pinned to their latest public release at benchmark freeze time and are applied to the full dataset D. Rule-based and static tools run with their bundled rule sets. Model-based tools use their published default models and checkpoints (DataSentinel, Attention Tracker, Llama Guard 3, Prompt Guard 2, and NeMo Guardrails), except for those that require an explicit backend choice: AI-Infra-Guard and Cisco Skill Scanner (LLM) use gpt-5.4-mini; Sentry Skill Scanner (full) uses claude-haiku-4-5-20251001; and MELON uses gpt-4o-mini. For the transferred prompt-injection defenses in RQ4, we concatenate SKILL.md with any accompanying scripts as a single input."
> "Supply-chain tools are run over the skill package as software artifacts, while prompt-injection defenses receive the concatenated SKILL.md and auxiliary files as input." (4.6)

지표: Table 5 컬럼 "Acc. | Prec. | Rec. | F1 | FP | FN". 임계값 조정 없음(툴 기본 출력 사용).

**skill 단위 verdict 도출 규칙은 논문에 명시되어 있지 않고 저장소 코드에 있다.** `Experiment/RQ3/baseline_accuracy.py` (https://github.com/lxyeternal/MalSkillBench/blob/main/Experiment/RQ3/baseline_accuracy.py):
- 평가 단위: `iter_dataset_skills()`가 `Dataset/Skills/{benign,malware}/<skill_dir>` 디렉터리 하나를 한 샘플로 순회 (skill 단위).
- Cisco: `"""Return True for malware when Cisco reports HIGH/CRITICAL severity."""` (`max_severity in {"CRITICAL","HIGH"}` → malware; `{"MEDIUM","LOW","INFO","SAFE"}` → benign)
- LLM Guard: `"""LLM Guard wrapper: RISK / High / Critical means malware."""`
- NMitchem skillscan: `"""NMitchem skillscan audit: raw FAIL/risk_score >= threshold means malware."""`
- PanGuard: `"""PanGuard LLM mode: raw HIGH/CRITICAL risk levels mean malware."""`
- skill-security-scan: HIGH/CRITICAL → malware, 없으면 `risk_score >= 6`
- Snyk: `"""Snyk Agent Scan: E-code issues mean malicious; W-code issues are warnings."""`
- getsentry: `GETSENTRY_MALWARE_RISK_LEVELS = {"critical", "high"}` / `GETSENTRY_BENIGN_RISK_LEVELS = {"medium", "low", "clean", "minimal"}`
- kurtpayne skillscan-security: `verdict == "block"` → malware; 주석 "Baseline wrapper maps BLOCK/score>=100 to RISK and WARN/score>=30 to ATTENTION. For binary classification, only RISK is malware."
- VirusTotal: `"""VirusTotal: raw completed analysis with malicious/suspicious engines means malware."""` (`malicious > 0 or suspicious > 0`)

`Baselines/skillsecurity/README.md`의 통일 verdict 체계:
> "**Unified verdict scheme** (used by `run_skill_scanner.py` in tools 5 and 6):
> - `SAFE` — no Medium+ issue detected
> - `ATTENTION` — sensitive capability present but justified by declared function
> - `RISK` — clear malicious behavior, exfiltration, or scope abuse"

요약: **skill 단위, 툴의 최고 심각도가 HIGH/CRITICAL(또는 RISK/BLOCK)이면 malicious**. MEDIUM 이하는 benign 처리. 이것이 MaliciousSkillBench의 Cisco 게이트("local HIGH/CRITICAL gate")와 같고 SkillFortify 게이트("MEDIUM+")와는 다르다.

### 2(b) "wild-only" 분석

4.5.3 Wild-Only Detection Performance 원문:
> "The aggregate results in Table 5 mix 3,214 generated samples with 703 wild samples. The generated subset spans the full taxonomy, whereas the wild sample is concentrated on a few patterns (RQ2), so the two can give very different readings of the same detector. Figure 7 contrasts each detector's recall on the full benchmark with its recall on the 703 wild skills alone. The wild subset contains no benign samples, so only recall is defined there, while precision and false positives carry over from Table 5."
> "Wild-only and full-benchmark evaluation rank detectors almost oppositely. The two detectors that look strongest on the full benchmark are not the strongest in the wild: on the 703 wild skills, Cisco LLM (98.2%) and VirusTotal (87.9%) lead, while AI-Infra-Guard slips to 74.0%. The reordering is large and crossing (Figure 7). VirusTotal climbs 66 points (21.6% to 87.9%) and Snyk 49 points (28.7% to 77.2%), each leapfrogging most of the field, while Cisco Static, Sentry Static, and AI-Infra-Guard fall by 13 to 21 points."
> "The wild sample is 86.6% Malware Delivery carried by dependency impersonation (RQ2), so it rewards detectors that key on delivered payloads and declared dependencies."

Table 6 (wild subset, 행동별 recall, 원문):

| Tool | B1 (18) | B2 (33) | B4 (609) | B9 (15) |
|---|---:|---:|---:|---:|
| VirusTotal | 16.7% | 9.1% | 99.3% | 6.7% |
| Cisco Skill Scanner (LLM) | 77.8% | 72.7% | 100.0% | 100.0% |
| Sentry Skill Scanner (full) | 83.3% | 81.8% | 97.0% | 100.0% |
| AI-Infra-Guard | 77.8% | 60.6% | 72.9% | 100.0% |

wild 검증 방식 (3.x):
> "Before any skill enters D_wild, two Ph.D. researchers with at least four years of security research experience reviewed its source code and markdown content, verified that it was genuinely malicious, and assigned taxonomy labels (v,b,s) following the coverage matrix in §3.1. ... The collection totals |D_wild|=703 confirmed-malicious skills from 50 distinct accounts on ClawHub. CI attacks account for the large majority, reflecting the scarcity of PI-based skill attacks in the wild."

benign 수집:
> "We collect 4,000 benign skills from ClawHub in descending order of download count ... These skills have passed the platform's security screening and rank among its most downloaded, so we treat them as a high-confidence benign set. False positives reported in §4 are measured against these 4,000 skills."

test-collected 27: "D_test comprises |D_test|=27 malicious skills extracted from the official test suites of existing detection tools."

### 2(c) 공개 데이터에 generated / wild 표시가 있는가

**행 단위 필드는 없다.** 데이터는 디렉터리 트리(`Dataset/Skills/malware/<name>/`, `Dataset/Skills/benign/<name>/`)이고, 구분은 별도 인벤토리 파일 `Dataset/Skills/malware/_source_inventory.txt`에 있다 (https://github.com/lxyeternal/MalSkillBench/blob/main/Dataset/Skills/malware/_source_inventory.txt). 헤더 원문:
```
# Total samples       : 3944
# Generated samples   : 3214
# Wild samples        : 703
# Test-collected      : 27
#   - testdddd        : 15
#   - malicious_test  : 12
# RQ2 true in-the-wild analysis uses WILD entries only: 703
```
행 형식: `GENERATED  <dir>  <-  generated_malicious/<VEC>/<Bxx>/<strategy>_<timestamp>` / `WILD  <dir>  <-  wild_malware/<author>/<skill>` / `TEST  <dir>  <-  wild_malware/testdddd/<case>`. 섹션: `GENERATED (3214)`, `WILD (703)`, `TEST (27)`, 그리고 `GENERATED BEHAVIOR LABELS (3214)`, `WILD BEHAVIOR LABELS (703)`, `TEST BEHAVIOR LABELS (27)`. `[계산]` 라벨 행 수: GENERATED 6,428(=3,214×2), WILD 1,406(=703×2), TEST 54(=27×2) 로 헤더와 일치.

디렉터리 이름의 `__<CI|PI|MIXED>_B<n>` 접미사는 동명 충돌 해소용일 뿐이며(인벤토리 "Strip the '__<VECTOR>_<Bxx>' disambiguation suffix if present"), 접미사 없는 generated도 많다(예: `GENERATED  1inch  <-  generated_malicious/CI/B9/function_append_...`). **따라서 벡터/행동 라벨은 반드시 인벤토리의 BEHAVIOR LABELS 섹션에서 읽어야 한다.**

`Experiment/RQ3/wild_baseline_detection.py` docstring: "Report RQ3 detector performance on true in-the-wild malicious skills only. ... 703 WILD entries recorded in Dataset/Skills/malware/_source_inventory.txt. Because every WILD entry is malicious, this report measures detection/recall".

각 skill 디렉터리는 README대로 "a complete, self-contained skill package — `SKILL.md` plus any `scripts/`, `references/`, or `assets/` it ships." (예: `Dataset/Skills/malware/3d-games__CI_B2/SKILL.md` + `scripts/asset_loader.py`). 참고: GitHub contents API는 디렉터리당 1,000개까지만 반환하므로 전체 트리는 `git/trees?recursive=1`로 받아야 하며 그것도 `truncated: true`가 나온다. 클론이 필요하다.

### 2(d) 택소노미 (3차원, 108셀)

README 원문:
> "Every malicious skill is labeled along three dimensions; the valid combinations form **108 cells** (`9x4` CI + `15x3` PI + `9x3` MIXED)."
> 1. Attack vector: `CI` "Code Injection: malicious code in scripts or inline code blocks" / `PI` "Prompt Injection: adversarial instructions in `SKILL.md`" / `MIXED` "The chain is split across markdown and code; malicious only when combined"
> 2. Malicious behavior "(B1-B9 work via CI/PI/MIXED; B10-B15 target the agent and are PI-only)": B1 Data Exfiltration, B2 Credential Theft, B3 Remote Code Execution, B4 Malware Delivery, B5 Persistence, B6 Reverse Shell, B7 Ransomware, B8 Resource Abuse, B9 Privilege Escalation, B10 Role Hijack, B11 Safety Bypass, B12 Instruction Override, B13 System Prompt Leak, B14 Goal Hijacking, B15 Content Manipulation
> 3. Insertion strategy: CI "New Script File, Function Append, Function Inject, Inline Code Block" / PI "Full Camouflage, Partial Injection, Steganographic" / MIXED "Download+Execute, Config+Load, Fetch+Run"

논문: "|C| = 9×4 (CI) + 15×3 (PI) + 9×3 (MIXED) = 108 cells". 생성 yield: "overall **85.6%** verification yield (CI 94.5%, MIXED 91.9%, PI 75.8%)".

### 2(e) 라이선스

- README 마지막 절: "## License\n\nFor academic research use only." — 그 외 조건 없음. 저장소에 LICENSE 파일 없음(루트 목록: `.gitignore, Baselines, Configs, Core, Dataset, Experiment, README.md, Utils`). GitHub API `license: null`.
- 논문 말미: "Our dataset, baselines, and evaluation pipeline are publicly available at https://github.com/lxyeternal/MalSkillBench."
- arXiv 페이지 헤더의 "License: CC Zero"는 arXiv 논문 텍스트 라이선스이지 데이터 라이선스가 아니다.
- MaliciousSkillBench Table 6이 SRC001 upstream license를 "academic-research-only", 정책을 "adapter only"로 기록.

### 2(f) 검출기 결과 표 (원문)

Table 5 (전체 3,944 malicious + 4,000 benign):

| Tool | Acc. | Prec. | Rec. | F1 | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Skill Security Scan | 43.9% | 28.5% | 8.7% | 13.3% | 858 | 3,602 |
| SkillScan | 54.5% | 70.0% | 14.5% | 24.0% | 244 | 3,374 |
| SkillScan-Security | 60.1% | 56.6% | 84.0% | 67.6% | 2,542 | 631 |
| Cisco Skill Scanner (static) | 63.2% | 78.5% | 35.6% | 49.0% | 384 | 2,541 |
| Cisco Skill Scanner (LLM) | 77.9% | 71.4% | 92.7% | 80.7% | 1,465 | 287 |
| AI-Infra-Guard | 85.6% | 84.6% | 86.6% | 85.6% | 620 | 527 |
| LLM Guard | 57.2% | 59.1% | 44.6% | 50.9% | 1,215 | 2,185 |
| Panguard Skill Auditor (static) | 56.7% | 76.2% | 18.6% | 29.9% | 229 | 3,211 |
| Snyk Agent Scan | 63.5% | 93.2% | 28.7% | 43.8% | 82 | 2,814 |
| Sentry Skill Scanner (static) | 57.7% | 67.3% | 28.7% | 40.2% | 548 | 2,814 |
| Sentry Skill Scanner (full) | 87.4% | 80.5% | 98.4% | 88.6% | 937 | 64 |
| VirusTotal | 61.0% | 99.5% | 21.6% | 35.5% | 4 | 3,093 |

(FP는 4,000 benign 대비. `[계산]` benign FPR: Sentry full 23.4%, AI-Infra-Guard 15.5%, Cisco LLM 36.6%, Cisco static 9.6%, Snyk 2.05%, VirusTotal 0.1%.)

벡터별 recall (4.5.2 본문):
> "Sentry Full stays high on CI, PI, and MIXED (99.8%, 97.6%, 99.8%), but the others drop sharply on PI: AI-Infra-Guard from 99.2%/99.1% on CI/MIXED to 74.8%, Cisco LLM from 96.5%/98.9% to 83.1%, and Cisco Static from 46.9%/72.0% to 18.7%."

행동별 recall은 Figure 6(a)에 그림으로만 있고 본문 수치는 일부: "Content Manipulation (B15) at 35.8% and 32.1%" (AI-Infra-Guard, Cisco LLM), "Cisco Static reaches 69.7% on Remote Code Execution and 70.5% on Reverse Shell, and VirusTotal 73.3% on Malware Delivery". 삽입전략별: "Cisco Static rises to 77.3% on Download+Execute and 71.6% on Fetch+Run", "Sentry Static drops to 5.1% on Partial Injection and 8.5% on Full Camouflage".

Table 7 (RQ4 이전 도구): Bandit4Mal 50.9% F1, GuardDog 26.5%, OSSGadget 67.5% (FP 3,587), MalGuard-MLP 26.2%, SAP-DT 66.9% (FP 3,858), DataSentinel 66.3% (FP 3,979), Llama Guard 3 22.8%, NeMo Guardrails 67.5% (FP 3,478), Prompt Guard 2 33.2%, MELON 24.8%, Attention Tracker 66.4% (FP 4,000, Rec 100%).

---

## 3. SkillGate (arXiv 2607.25619v1) + SkillsBench-1650

출처
- 논문 HTML: https://arxiv.org/html/2607.25619v1 (arXiv 헤더 "License: CC BY 4.0"은 논문 텍스트 라이선스)
- 데이터: https://huggingface.co/datasets/zenith6888/SkillsBench-1650 (cardData.license: cc-by-4.0, gated: false, 파일 `benign.parquet`, `malicious.parquet`, lastModified 2026-04-09)

### 3(a) 지표 정의 (III-G2 원문)

> "We report Precision (P), Recall (R), F1, and False Positive Rate (FPR). We additionally report the Matthews Correlation Coefficient (MCC), defined as MCC = (TP·TN − FP·FN) / sqrt((TP+FP)(TP+FN)(TN+FP)(TN+FN)), which ranges over [−1,1] (1 = perfect, 0 = no better than chance, <0 = anti-correlated). Unlike F1, MCC incorporates all four confusion-matrix cells so it is not inflated by a classifier that simply flags most inputs."
> "AUPRC (Area Under the Precision-Recall Curve) serves as the primary threshold-independent metric, computed from a per-sample malicious-likelihood score. For SkillGate, prefilter-safe files (no LLM call) receive score 0; for files sent to the judge, the score is the model's confidence when it labels the file malicious and 1−confidence otherwise, so that higher scores rank more-suspicious files first. Baseline scores use each tool's native ranking signal (ClawVet's numeric risk score; SkillScanner's severity rank). We compute AUPRC as the average precision over the resulting ranking. All results were computed over a three run average to account for LLM nondeterminism, with standard deviations reported."

FPR 공식은 논문에 별도로 안 쓰여 있고, 수치로 확인된다: "SkillGate produces on average 17 false positives (FPR=1.13%)" → 17/1,500 = 1.13% `[계산 일치]`; "ClawVet reaches F1=0.258 at FPR=50.4% (756/1,500 false positives)"; Table V 제목 "False-positive breakdown on SkillsBench (1,500 benign files)".

### 3(b) 평가 단위: file

III-F:
> "We evaluate on SkillsBench [23], an open-source benchmark of skill files. SkillsBench comprises 1,500 real-world benign skills sourced from public repositories and 150 hand-crafted malicious skills spanning 8 attack categories, giving a total evaluation set of n=1,650 files with 9.1% malicious prevalence."

논문 전체가 "files"로 센다 ("catching 135/150 malicious files", "406 benign ones (FPR=27.1%)"). skill 단위 집계 규칙은 없다. 단, HF 데이터셋 구조상 **1행 = 1 skill** (필드 `content` = SKILL.md 전체, `script_content` = "Concatenated companion script contents", `script_files` = JSON list)이라 file 단위 = skill 단위로 봐도 된다. 우리가 skill 단위로 평가해도 이 데이터셋에서는 같은 분모(1,500 / 150)가 나온다.

### 3(c) 운영 임계값

> "The pre-specified default θ=0.70 yields F1=0.817, R=0.769, FPR=1.13%. The F1-optimal threshold (θ≈0.14) achieves F1=0.842, R=0.824, FPR=1.33% ... A realisitc deployabile FPR (<5%) holds across essentially the whole range θ∈[0.06,0.99]" (V Threshold sensitivity)
> 정책 매핑 (III-D): "MALICIOUS (confidence≥0.7) → BLOCK; SUSPICIOUS (confidence≥0.5) → QUARANTINE."
> 베이스라인: "ClawVet and SkillScanner+LLM are evaluated at their oracle-optimal thresholds on the test set." / "Oracle-optimal thresholds for ClawVet and SkillScanner favor those baselines; reported comparisons are therefore conservative."

프리필터 규칙: "By default, files with zero hits are immediately classified SAFE with no LLM call is made ... Critically, the prefilter is a gate, not a classifier: a matched pattern hit does not produce a final label. All labelling decisions are deferred to the LLM judge in Stage 3."

### 3(d) 결과 표 (원문)

Table II (SkillsBench n=1,650):

| Method | AUPRC | Prec | Recall | F1 | MCC | FPR | LLM calls |
|---|---:|---:|---:|---:|---:|---:|---:|
| SkillGate (ours) | 0.830 | 0.875 | 0.769 | 0.817 | 0.803 | 1.13% | 540 |
| ClawVet† | 0.144 | 0.151 | 0.893 | 0.258 | 0.225 | 50.40% | 0 |
| SkillScanner ≥INFO | 0.162 | 0.087 | 0.820 | 0.157 | −0.037 | 86.47% | 0 |
| SkillScanner ≥LOW | | 0.205 | 0.480 | 0.287 | 0.206 | 18.67% | 0 |
| SkillScanner ≥MEDIUM | | 0.214 | 0.473 | 0.295 | 0.215 | 17.40% | 0 |
| SkillScanner ≥HIGH | | 0.345 | 0.067 | 0.112 | 0.118 | 1.27% | 0 |
| SkillScanner ≥CRITICAL | | 0.438 | 0.047 | 0.084 | 0.119 | 0.60% | 0 |
| SkillScanner+LLM† | 0.246 | 0.710 | 0.180 | 0.287 | 0.331 | 0.73% | 1650 |

"†ClawVet and SkillScanner+LLM thresholds are oracle-optimal on each test set. ... SkillGate per-run std: F1 0.013, AUPRC 0.016, MCC 0.019, FPR 0.59pp." SkillScanner = "the Cisco AI Defense multi-engine scanner (v2.0.11)"; LLM judge = gpt-5.4-mini.

Table VI (ablation) — **우리 2단계 구조와 가장 직접 비교되는 표**:

| Config | Prec | Recall | F1 | MCC | FPR | LLM calls |
|---|---:|---:|---:|---:|---:|---:|
| B1 (pure regex, no LLM) | 0.250 | 0.900 | 0.391 | 0.385 | 27.1% | 0 |
| B2 (full-file LLM, no prefilter) | 0.822 ±.031 | 0.804 ±.010 | 0.813 ±.011 | 0.794 ±.013 | 1.76% ±.38 | 1650 |
| SkillGate ms=5 snippets | 0.856 ±.054 | 0.762 ±.020 | 0.806 ±.015 | 0.789 ±.019 | 1.31% ±.57 | 540 |
| SkillGate (default, ms=20) | 0.875 ±.058 | 0.769 ±.020 | 0.817 ±.013 | 0.803 ±.019 | 1.13% ±.59 | 540 |

> "The prefilter alone flags any file with a pattern hit, catching 135/150 malicious files (R=0.900) but also 406 benign ones (FPR=27.1%)"

카테고리별 recall: **논문에는 없다.** 하지만 HF 데이터셋에 `attack_type`(8종, 각 18~19개)과 `difficulty`(easy 50 / medium 52 / hard 48) 필드가 있어 우리가 직접 계산할 수 있다. 8 attack_type과 카운트(HF README): plaintext_cmd 19, encoded_payload 19, remote_script 19, steganography 18, rsa_modular 19, ascii_smuggle 19, binary_exec 19, data_exfil 18.

데이터 성격 (HF README): "Malicious samples are synthetically constructed by injecting attack payloads into real benign skill hosts" / "Selected 50 benign skills (3,000-15,000 chars) as injection hosts" / benign "With companion scripts: 285 / 1,500 (19%)". 즉 SkillsBench-1650 malicious는 전부 합성(injected)이고 benign은 실세계다.

---

## 4. SkillVetBench (arXiv 2606.15899) + companion (arXiv 2606.00925)

출처
- 2606.15899: https://arxiv.org/html/2606.15899 "SkillVetBench: LLM-as-Judge for Multi-Dimensional Security Risk Evaluation in Open-Source LLM Agent Skills"
- 2606.00925: https://arxiv.org/html/2606.00925 "Benchmarking Security Risk Detection and Verification in Open Agentic Skill Ecosystems" (Hossain, Puppala, Lu, Talukder, Jiang; UTEP SUPREME Lab). arXiv 헤더 "License: CC BY 4.0"은 논문 라이선스.
- 코드: https://github.com/supreme-lab/SkillVetBench (LICENSE 파일은 Apache License 2.0; README 말미는 "MIT License — see `LICENSE` for details."로 불일치)
- 리더보드: https://huggingface.co/spaces/supreme-lab/AgentSkillBench (HTTP 200 확인)

### 4(a) 78+22 라벨셋의 구성과 사용

2606.15899 Section 5:
> "The results in this section come from the controlled, labeled evaluation of the companion benchmark [1]: 78 confirmed-malicious skills and 22 benign controls (100 total). This is a different population from the live-leaderboard corpus analyzed in Section 7 (1,299 skills)"

2606.00925 4.1:
> "To answer RQ1, we evaluated SkillVetBench against eight baselines on 78 confirmed-malicious skills and 22 benign controls from ClawHub, spanning seven vulnerability categories plus benign controls. Each skill was submitted independently; verdicts (Malicious, Suspicious, Benign) were recorded per method. The primary safety metric is the False Negative Rate (fnr), since missed detections directly expose users to active threats."

수집 (Appendix D.1): "We collected skills directly from the live ClawHub marketplace at clawhub.ai ... We downloaded a corpus of 100 skills spanning a range of functional categories ... including Auto-Updaters, ClawHub Typosquats, Ethereum Gas Trackers, Polymarket integrations, Wallet Trackers, X/Twitter Trends analyzers, Yahoo Finance connectors, YouTube Summarizers, and YouTube Video Downloaders."
윤리 절: "All malicious samples are drawn from skills already flagged by public scanners—we synthesize no new payloads."

즉 **100개 전부 실세계(ClawHub, ClawHavoc 캠페인 포함)**이고 합성은 없다. 다만 "confirmed-malicious"의 근거가 "already flagged by public scanners" + LLM judge + 일부 sandbox라 라벨 강도는 MalSkillBench wild(박사 2인 검토)보다 약하다.

### 4(b) 결과 (원문)

2606.15899 Table 3 "Detection performance on 78 malicious + 22 benign skills" (System | Balance | Catch | Precision | Miss %):

| System | Balance | Catch | Precision | Miss % |
|---|---:|---:|---:|---:|
| VirusTotal | 0.46 | 0.33 | 1.00 | 67% |
| ClawScan | 0.56 | 0.48 | 1.00 | 52% |
| ClawVet | 0.53 | 0.41 | 1.00 | 59% |
| LLM (0-shot) | 0.76 | 0.74 | 0.87 | 26% |
| LLM (few-shot) | 0.80 | 0.78 | 0.88 | 22% |
| CodeBERT | 0.68 | 0.70 | 0.95 | 30% |
| SkillProbe | 0.82 | 0.81 | 0.88 | 19% |
| SkillSieve | 0.84 | 0.85 | 0.90 | 15% |
| SkillVetBench (Ours) | 0.95 | 1.00 | 0.96 | 0% |

> "with 78/78 recall the lower bound is ≈0.95 (true miss rate could be up to ∼5%), and with 22/22 specificity the lower bound is ≈0.85" (Wilson 95%)

2606.00925 Table 2 (카테고리별 verdict 수, 형식 Malicious/Suspicious/Benign; 탐지 = Malicious 또는 Suspicious):

| Category | SkillVetBench | ClawScan | VirusTotal | ClawVet | LLM 0-shot | LLM few-shot | CodeBERT | SkillProbe | SkillSieve |
|---|---|---|---|---|---|---|---|---|---|
| Command Injection (27) | 5/22/0 | 0/13/14 | 0/9/18 | 0/11/16 | 0/20/7 | 0/21/6 | 0/19/8 | 0/22/5 | 0/23/4 |
| Prompt Injection (19) | 0/19/0 | 0/3/16 | 0/0/19 | 0/2/17 | 0/12/7 | 0/13/6 | 0/0/19 | 0/14/5 | 0/15/4 |
| Unsafe File Ops (10) | 0/10/0 | 0/5/5 | 0/2/8 | 0/4/6 | 0/7/3 | 0/8/2 | 0/6/4 | 0/8/2 | 0/8/2 |
| Memory Poisoning (9) | 1/8/0 | 0/1/8 | 0/3/6 | – | – | – | – | – | – |
| Data Exposure (5) | 0/5/0 | 0/4/1 | 0/0/5 | 0/1/4 | 0/3/2 | 0/4/1 | 0/2/3 | 0/4/1 | 0/4/1 |
| Supply Chain (4) | 0/4/0 | 0/1/3 | 0/1/3 | 0/1/3 | 0/2/2 | 0/3/1 | 0/2/2 | 0/3/1 | 0/3/1 |
| Privilege Abuse (4) | 0/4/0 | 0/2/2 | 0/0/4 | 0/1/3 | 0/2/2 | 0/3/1 | 0/2/2 | 0/3/1 | 0/3/1 |
| No Issue (22 benign) | 0/0/22 | 0/1/21 | 0/2/20 | 0/1/21 | 0/3/19 | 0/2/20 | 0/0/22 | 0/2/20 | 0/1/21 |

> "ClawScan misses 52% of Command Injection, 84% of Prompt Injection, 89% of Memory Poisoning, and 75% of Supply Chain skills. VirusTotal is worse on semantic categories: 100% fnr on Prompt Injection, Data Exposure, and Privilege Abuse, and 67% on Command Injection."

주의: SkillVetBench의 "탐지"는 Suspicious까지 포함한다. SkillVetBench 자체 verdict 중 Malicious는 78개 중 6개뿐(5+1)이고 나머지 72개는 Suspicious다. 우리가 binary로 비교하려면 "Suspicious 포함" 조건을 명시해야 한다.

### 4(c) 라벨셋 다운로드 가능 여부

- **HF 데이터셋으로 공개된 78+22 라벨셋은 없다.** 2606.00925: "Code is available at: https://github.com/supreme-lab/SkillVetBench/tree/master." 2606.15899 Appendix A: "Per-skill reports, SKV findings, and CSV export are publicly available via the Hugging Face Space at https://huggingface.co/spaces/supreme-lab/AgentSkillBench." (이는 1,299개 라이브 리더보드 CSV이지 100개 라벨셋이 아니다.)
- 저장소 `data/`에 `malicious_slugs.txt` (342행; `malicious_skills.txt`에 "Malicious Skills (341 total)", "ClawHavoc Campaign (335 skills)"), `skills_contain_attack_patterns.json` (ClawHub slug + `oc_verdict`/`vt_verdict` + 패턴 hit), `agentskillbench_full_leaderboard.csv`가 있다. 78개 malicious + 22 benign의 정확한 slug 목록 파일은 못 찾았다. `results/evaluation_category_tables.tex`에 100개 기준 카테고리별 표(Command/Shell Injection 27, benign 22, Prompt Injection 19, Unsafe File Ops 10, Memory Poisoning 9, Credential/Secret Exposure 4, RCE 3, Agentic State Manipulation 2, Supply Chain 1, Scope Creep 1, Privilege Escalation 1, Data Exfiltration 1)가 있어 논문 7카테고리와 매핑이 조금 다르다.
- skill 본문은 ClawHub에서 slug로 재수집해야 하며(`clawhub install <slug>`), ClawHavoc 캠페인 skill은 이미 마켓에서 내려갔을 수 있다. 재현 불확실성이 크다.
- 결론: 우리 1주차 범위에서는 SkillVetBench 라벨셋은 **재현 대상이 아니라 "수치 인용" 대상**으로만 쓴다.

---

## 5. 우리 권고 프로토콜

### 5.1 평가 단위

- **skill(패키지) 단위.** 파일별 판정은 max-severity로 skill에 집계한다 (MalSkillBench 코드와 동일: 최고 심각도 HIGH/CRITICAL → malicious).
- MaliciousSkillBench에서는 **`skill_text` 단일 텍스트 입력**을 기본 조건으로 한다 (benign은 패키지가 없어 스크립트 입력이 비대칭이기 때문). `packages/`의 스크립트까지 넣는 조건은 "package-level" 별도 조건으로 표기하고 malicious recall만 비교한다.
- SkillsBench-1650은 1행 = 1 skill이므로 `content` + `script_content`를 함께 넣으면 SkillGate와 같은 입력이 된다.

### 5.2 보고할 분할 (우선순위 순)

1. **MaliciousSkillBench Source-Disjoint test (1,384 = 839 M / 545 B)**: 기존 스캐너·Word-SVM 수치와 같은 표에 놓는 유일한 분할. 우리 검출기는 학습이 없으므로 train/val은 쓰지 않지만 반드시 "test 분할만" 보고한다 (learned 베이스라인과 조건 일치).
2. **MaliciousSkillBench Random test (1,948 = 1,501 M / 447 B)**: Word-SVM Random Macro-F1 0.932 옆. 학습 없는 우리에게는 사실상 무작위 부분집합.
3. **MaliciousSkillBench 전체 9,740 → provenance별**: `wild` (1,936 B / 229 M), `injected` (153 B / 3,341 M), `synthetic` (90 B / 250 M), `backdoored` (0 / 159), `test_fixture` (56 / 100), `mixed_unresolved` (0 / 3,426, SRC001). 실세계 vs 합성은 여기서만 유의미하다. `mixed_unresolved`는 별도로 두고 합치지 않는다. 학습이 없으니 전체를 써도 누수는 없지만, "frozen split" 규약과 다르므로 "전체 9,740, 학습 없음"을 조건으로 명기.
4. **MaliciousSkillBench 전체 attack category별 recall (4,983 mapped)**: 11개 카테고리 multi-label. 문헌에 없는 새 숫자가 된다. SD test만으로는 237개라 소표본.
5. **SkillsBench-1650 (1,500 B / 150 M)**: SkillGate Table II·VI와 직접 비교. `attack_type` 8종 × `difficulty` 3단계별 recall도 계산(문헌에 없음).
6. **MalSkillBench (3,944 M / 4,000 B) + wild-only 703 recall**: 데이터를 클론해 쓸 수 있으면(academic-only 조건 충족) Table 5·6과 비교. 벡터별(CI/PI/MIXED), 행동별(B1~B15)은 `_source_inventory.txt`에서 읽는다. 2주차 이후 후보.

### 5.3 지표

- 점수가 있는 2단계(LLM judge confidence)와 결합 점수에는 **PR-AUC(average precision)**, **recall@1%FPR**. 점수가 없는 1단계(규칙 hit 여부)는 운영점만.
- 문헌 비교용 고정 임계값 운영점: **Macro-F1, malicious recall, benign FPR** (MaliciousSkillBench 형식) + **F1, Precision, MCC, FPR** (SkillGate 형식). 임계값은 실행 전에 정해 두고("pre-specified"), 검증셋 튜닝 안 함 (두 논문 모두 그렇게 했다).
- LLM judge는 **3회 실행 mean ± std** (SkillGate 관행).
- 두 단계를 **독립 실행**한 뒤 skill별 union / intersection / (S1 only, S2 only)를 표로. 이는 SkillGate Table VI의 B1(regex only) / B2(full-file LLM) / 결합에 대응한다.
- 클래스 정의: malicious = positive = 1.

### 5.4 문헌에 이미 있는 숫자 (우리 결과를 옆에 놓을 수 있는 것)

| 데이터/분할 | 방법 | 수치 | 조건 | 출처 |
|---|---|---|---|---|
| MSB Source-Disjoint test 1,384 | Word TF-IDF+SVM | Macro-F1 0.665, recall 0.956, FPR 0.624 | 학습 모델, skill_text만, 3-seed 평균 | 2608.19901 Table 3; repo scanner_eval CSV |
| 〃 | Cisco-local-behavioral | 0.308 / 0.025 / 0.011 | HIGH/CRITICAL gate, local env | 〃 |
| 〃 | SkillFortify-offline | 0.349 / 0.253 / 0.499 | MEDIUM+ gate; SRC012 겹침 이득 | 〃 |
| 〃 | SkillSpector-static | 0.281 / 0.000 / 0.0055 | LLM 비활성 | 〃 |
| 〃 SRC011 benign 455 | FP 수 | Word-SVM 293, SkillFortify 272, Cisco 6, SkillSpector 3 | | 2608.19901 6.4 |
| MSB Random test 1,948 | Word-SVM | Macro-F1 0.932, FPR 0.094 | | Table 2 |
| MSB M-Struct.-Disjoint | Word-SVM | Macro-F1 0.916 | | Table 2 |
| MSB SD AUROC | 3 text models | 0.738–0.821 (Random 0.965–0.986) | AUPRC 값 미공개 | Appendix I |
| SkillsBench-1650 | SkillGate default θ=0.70 | AUPRC 0.830, P 0.875, R 0.769, F1 0.817, MCC 0.803, FPR 1.13% | file 단위, gpt-5.4-mini, 3-run mean | 2607.25619 Table II |
| 〃 | B1 regex only | P 0.250, R 0.900, F1 0.391, MCC 0.385, FPR 27.1% | 530-pattern ruleset | Table VI |
| 〃 | B2 full-file LLM | R 0.804, F1 0.813, FPR 1.76% | 1,650 LLM calls | Table VI |
| 〃 | Cisco SkillScanner ≥MEDIUM | F1 0.295, FPR 17.40% | v2.0.11 | Table II |
| 〃 | SkillScanner ≥HIGH | R 0.067, FPR 1.27% | | Table II |
| 〃 | ClawVet (oracle) | AUPRC 0.144, F1 0.258, FPR 50.4% | | Table II |
| MalSkillBench 3,944+4,000 | Sentry (full) | Rec 98.4%, F1 88.6%, FP 937 | claude-haiku-4-5 | 2606.07131 Table 5 |
| 〃 | AI-Infra-Guard | Rec 86.6%, F1 85.6%, FP 620 | gpt-5.4-mini | 〃 |
| 〃 | Cisco (LLM) / (static) | Rec 92.7% / 35.6%, FP 1,465 / 384 | | 〃 |
| 〃 | VirusTotal | Rec 21.6%, FP 4 | | 〃 |
| 〃 벡터별 | Sentry full / AI-Infra-Guard / Cisco LLM / Cisco static | CI-PI-MIXED: 99.8/97.6/99.8, 99.2/74.8/99.1, 96.5/83.1/98.9, 46.9/18.7/72.0 | | 4.5.2 |
| MalSkillBench wild 703 | Cisco LLM / VirusTotal / Snyk / AI-Infra-Guard | recall 98.2% / 87.9% / 77.2% / 74.0% | benign 없음, recall만 | 4.5.3 |
| 〃 wild 행동별 | Table 6 | 위 2(b) 표 | B1 18, B2 33, B4 609, B9 15 | Table 6 |
| SkillVetBench 78+22 | SkillVetBench / SkillSieve / VirusTotal / ClawScan | Catch 1.00 / 0.85 / 0.33 / 0.48, FP 0 / 1 / 2 / 1 (of 22) | Suspicious 포함 탐지, 실세계 ClawHub | 2606.15899 Table 3; 2606.00925 Table 2 |
| 〃 카테고리별 | Table 2 | 위 4(b) 표 | | 2606.00925 Table 2 |

### 5.5 비교 시 반드시 적을 조건

- MaliciousSkillBench 베이스라인은 **학습된** 모델(Word-SVM)과 **고정 게이트** 스캐너의 "operational comparison"이다. 우리는 학습 없는 규칙+LLM이므로 스캐너 쪽(Cisco/SkillFortify/SkillSpector)이 공정한 비교 대상이고, Word-SVM은 참고선이다.
- 우리 FPR 1%가 "recall@1%FPR"이면 Cisco-local-behavioral(FPR 1.1%, recall 2.5%)과 SkillScanner ≥HIGH(FPR 1.27%, R 0.067) 옆에 놓인다. 이게 가장 설득력 있는 자리다.
- MSB SD test의 wild malicious는 7개뿐이므로 "실세계 malicious recall"은 전체 229개(주로 SRC002/004/005 = MaliciousAgentSkillsBench, SkillLeakBench, Agent Skill Malware) 위에서 낸다.
- 카테고리별 결과는 multi-label이라 합이 100%가 아니며, 매핑 안 된 2,522개 malicious는 "unmapped"로 따로 둔다 ("Do not interpret empty taxonomy lists as 'no threat.' They mean 'not mapped.'" — schema.md).

---

## 6. 확인 못 한 것 / 열린 질문 ([B])

- MaliciousSkillBench가 SRC009/011/012를 고른 이유: 논문·저장소 어디에도 없음. 추정하지 않는다.
- MaliciousSkillBench 학습 베이스라인의 AUPRC 정확값: Appendix I에 "numerically high"라고만. 보조 자료(release archive)에 있을 수 있으나 확인 안 함.
- MalSkillBench 저장소 전체 트리는 GitHub API가 truncated를 반환해 3,944+4,000 디렉터리 존재를 API로는 완전 확인 못 함(`_source_inventory.txt` 카운트로만 확인). 클론 후 검증 필요.
- SkillVetBench 78+22의 slug 목록 파일: 저장소에서 못 찾음. 저자 문의 또는 `data/skills_contain_attack_patterns.json`·`clawhavoc_scan_summary.json` 대조 필요.
- SkillVetBench 저장소 라이선스: LICENSE 파일 Apache-2.0 vs README "MIT" 불일치.
- MaliciousSkillBench `packages/`에 SRC009·SRC010 아카이브가 올라와 있는 것과 논문 Table 6의 "metadata/hash only" 정책의 불일치: 논문 이후 갱신으로 보이나 확인 안 함. SRC010 upstream이 CC-BY-NC-SA-4.0인 점은 변하지 않는다.
