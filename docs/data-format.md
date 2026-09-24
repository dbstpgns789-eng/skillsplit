# 데이터 형식과 평가 입출력 규약

세 사람이 서로 기다리지 않도록, 데이터(대표)와 탐지기(팀원) 사이의 경계를 파일 두 종류로 고정한다. **탐지기 담당자는 `manifest.csv`만 읽고 `predictions.csv`만 쓴다.** 나머지는 평가 스크립트가 한다.

## 1. `data/manifest.csv` (대표가 만든다)

한 줄이 스킬 하나다. 스킬 파일 자체는 `data/raw/` 아래에 있고 git에 올리지 않는다(라이선스와 크기 때문). manifest는 올린다.

| 열 | 뜻 | 값 |
|---|---|---|
| `skill_id` | 고유 ID. `<dataset>:<원본 이름>` | `msb:0x-swap`, `stb:case_04866`, `asb:ASB04_000001` |
| `dataset` | 출처 벤치마크 | `malskillbench` / `skilltrustbench` / `maliciousskillbench` |
| `path` | 스킬 폴더의 상대 경로 (`data/raw/` 기준). 텍스트만 있는 스킬(MaliciousSkillBench 정상)은 `MaliciousSkillBench/text/<id>`이고 `taxonomy`의 `text_only`가 true | `MalSkillBench/Dataset/Skills/malware/0x-swap` |
| `label` | 이진 라벨. 1 = 악성, 0 = 정상 | `1` / `0` |
| `label3` | 3등급 라벨(있는 경우). SkillTrustBench의 `suspicious`(취약)는 이진에서 0으로 둔다 | `malicious` / `suspicious` / `normal` / 빈 값 |
| `origin` | 원본 벤치마크가 준 출처 표시 그대로 | `wild`, `generated`, `injected`, `safe_pool`, `mixed_unresolved` ... |
| `origin_group` | 출처를 세 묶음으로 정규화 | `real` (실제 유포) / `synthetic` (연구자가 만듦) / `unknown` (구분 안 됨) |
| `vector` | 공격이 어디에 있나. MalSkillBench 라벨 기준 | `CI` (코드) / `PI` (설명서 글) / `MIXED` (둘 다) / 빈 값 |
| `taxonomy` | 원본 벤치마크의 세부 라벨을 JSON 문자열로 보존. 키는 벤치마크마다 다르다. MalSkillBench `behavior`, `detail`. SkillTrustBench `risk_labels`, `attack_pattern`, `primary_pattern`, `base_category`, `trigger_type`, `encoding`. MaliciousSkillBench `attack_categories`, `evidence_type`, `source_id`, `source_disjoint`, `random`, `text_only` | `{"behavior": "B4", "detail": "Malware Delivery  New Script File  <name>"}` |
| `split` | 개발용 / 최종 평가용 | `dev` / `test` |
| `n_files` | 스킬 폴더의 파일 수. **manifest를 만든 기계의 디스크 기준** | 정수 |
| `files_expected` | 원본 압축 파일 기준 파일 수 (`data/index_archives.py`) | 정수 / 빈 값 |
| `intact` | `n_files >= files_expected`이면 1. 0이면 백신이 파일을 격리했거나 압축 해제가 실패한 것. 평가 스크립트는 0인 행을 건너뛴다 | `1` / `0` / 빈 값 |
| `has_script` | `.py .sh .bash .zsh .js .ts .mjs` 파일이 하나라도 있으면 1 | `1` / `0` |
| `skill_md_chars` | SKILL.md 길이(바이트) | 정수 |

**분할 규칙.** `dataset × label × origin_group`으로 층화해서 무작위로 나눈다. `dev` 30%, `test` 70%. 시드 42. 분할은 **원본 압축 파일 기준(`files_expected`)** 으로 정하므로 `_expected_files.json`과 같은 스킬 폴더 집합이 디스크에 있으면 누가 어느 기계에서 만들어도 같다. 폴더 집합이 다르면 분할이 달라지며 `manifest.sha256`으로 감지한다. 백신 격리는 `intact` 열에만 반영된다. 규칙을 고치거나 프롬프트를 바꾸는 동안에는 `dev`만 본다. `test`는 5주차 최종 평가 때 한 번 본다. manifest를 다시 만들면 SHA-256을 `data/manifest.sha256`에 적고, 그 뒤로는 바꾸지 않는다.

**왜 `origin_group`인가.** 우리가 만든(또는 연구자가 만든) 샘플은 규칙에 잘 잡히는 모양이 되기 마련이라, 실제 유포 샘플과 따로 재야 한다. 벤치마크마다 표기가 달라서(`wild`, `generated`, `injected`, `mixed_unresolved`) 세 묶음으로 정규화한다.

| 벤치마크 | `real` | `synthetic` | `unknown` |
|---|---|---|---|
| MalSkillBench | `wild`, `test`(도구 동봉 실제 샘플), `benign_top_downloaded`(정상 4,000) | `generated` | 없음 |
| SkillTrustBench | `wild`, `wild_expanded`, `wild_diffused`, `external_overtly_malicious_skills`, `safe_pool`(정상 씨앗) | `injected*` | 없음 |
| MaliciousSkillBench | `wild` | `injected`, `synthetic`, `backdoored`, `test_fixture` | `mixed_unresolved` |

## 2. `predictions.csv` (탐지기 담당자가 만든다)

한 줄이 스킬 하나다. 파일 이름은 `runs/<stage>_<version>_<YYYYMMDD>.csv`.

| 열 | 뜻 |
|---|---|
| `skill_id` | manifest의 값 그대로 |
| `score` | 0.0 ~ 1.0. 클수록 악성. **모든 스킬에 대해 반드시 값이 있어야 한다.** 판정 불가(파일 없음, API 오류)면 `score`를 비우지 말고 `error` 열에 사유를 적고 `score`는 0.0 |
| `verdict` | 선택. `MALICIOUS` / `SUSPICIOUS` / `SAFE` 같은 원래 판정 |
| `evidence` | 선택. 걸린 규칙 이름이나 LLM 근거 한 줄 (JSON 문자열) |
| `error` | 선택. 오류 사유 |

점수를 어떻게 만들지는 담당자가 정한다. 1단계는 예를 들어 "걸린 규칙의 최대 심각도"(NONE 0, LOW 0.25, MEDIUM 0.5, HIGH 0.75, CRITICAL 1.0)나 "가중 합을 0~1로 눌러 넣기"다. 2단계는 LLM이 낸 확신도다. 기준선 도구도 같은 형식으로 변환한다.

## 3. `eval/evaluate.py` (대표가 소유, 누구나 실행)

```
python eval/evaluate.py --manifest data/manifest.csv \
    --pred stage1=runs/stage1_v1_20261010.csv \
    --pred stage2=runs/stage2_v1_20261017.csv \
    --split dev
```

내는 것:
- 예측 파일마다: PR-AUC, FPR 1%에서의 재현율, 임계값 0.5에서의 정밀도·재현율·F1·FPR. 전체 / `origin_group`별 / `vector`별 / `dataset`별
- 예측 파일이 둘 이상이면: 임계값을 넘긴 것끼리 합집합·교집합·차집합 표 (악성 중 "1단계만 잡음 / 2단계만 잡음 / 둘 다 / 둘 다 놓침")

지표 정의는 scikit-learn의 `average_precision_score`(PR-AUC)와 `roc_curve`(FPR 1%에서의 재현율은 FPR ≤ 0.01인 지점 중 최대 TPR)를 쓴다. 손으로 계산하지 않는다.

## 4. 이 형식을 정한 이유

- 두 단계와 기준선이 전부 같은 `predictions.csv`를 내면, 평가 코드가 하나로 끝나고 누구든 자기 결과를 스스로 확인할 수 있다
- `score`가 연속값이어야 PR-AUC와 FPR 1% 재현율을 계산할 수 있다. 0/1만 내면 임계값 하나짜리 점밖에 못 찍는다
- `origin_group`과 `vector`가 manifest에 있어야 "1단계는 CI를 잡고 2단계는 PI를 잡는가", "실제 샘플에서 어느 단계가 더 무너지나"를 표 한 장으로 낼 수 있다
