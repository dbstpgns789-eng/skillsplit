# 데이터: 무엇을 쓰고 왜 그렇게 나누나

2026-09-25~26 밤에 세 벤치마크를 전부 내려받아 직접 센 결과다. manifest는 23,204행(dev 6,962 / test 16,242)이다. 수치는 `data/build_manifest.py`가 만든 `data/manifest.csv`(SHA-256 `data/manifest.sha256`)에서 나왔다.

## 1. 세 벤치마크의 실제 모양

| | MalSkillBench | SkillTrustBench | MaliciousSkillBench |
|---|---|---|---|
| 출처 | arXiv 2606.07131, github.com/lxyeternal/MalSkillBench | HF cuhk-zhuque/SkillTrustBench (Tencent Zhuque Lab) | arXiv 2608.19901, HF ProtectSkills/MaliciousSkillBench + github.com/protectskills/MaliciousSkillBench |
| 악성 | 3,944 (생성 3,214 + 실제 703 + 도구 동봉 27) | 2,863 (+ 의심 1,014) | 7,505 |
| 정상 | 4,000 (다운로드 상위 스킬) | 1,643 (씨앗 풀 1,500 등) | 2,235 |
| **정상 스킬의 파일** | SKILL.md + 부속 파일(스크립트는 19%) | SKILL.md + 스크립트 (완전한 케이스 폴더) | **SKILL.md 본문만** (패키지는 악성에만 제공) |
| 실제/합성 구분 | `_source_inventory.txt`에 GENERATED / WILD / TEST | `ground_truth.json`의 `source` (injected / safe_pool / wild ...) | `provenance` 필드 (wild / injected / synthetic / mixed_unresolved ...) |
| 공격 분류 | 벡터 CI / PI / MIXED × 행동 B1~B15 × 삽입 전략 (108칸). 실제 703건도 행동 라벨 있음 | 위험 T01~T09, 공격 패턴 코드, 트리거 유형, 인코딩 | 공격 범주 11개 (다중 라벨, 2,522건은 미분류) |
| 라벨 등급 | 2 | **3 (malicious / suspicious / normal)** | 2 |
| 라이선스 | "For academic research use only" (README에 이 한 줄만 있고 LICENSE 파일 없음. 재배포는 하지 않는 것으로 해석) | CC BY-NC-SA 4.0 | 코드 Apache-2.0, 메타데이터 CC BY 4.0, 스킬 본문은 각 출처의 조건 |
| 받는 법 | GitHub tarball 약 540 MB(받은 파일 540,338,547 바이트)에서 `Dataset/Skills`만 | HF zip 77 MB(카드 기준) | HF 저장소 약 34 MB(primary.parquet 28.6 MB) + GitHub `packages/*.tar.gz` 65 MB |

MaliciousSkillBench는 13개 출처의 통합판이고, 그 안에 MalSkillBench(3,426건, 행 단위 실제/생성 구분 없음 = `mixed_unresolved`)와 SkillTrustBench(4,426건)가 이미 들어 있다. 세 벤치마크는 서로 겹친다. 같은 스킬이 두 벤치마크에 다른 ID로 들어 있을 수 있으므로, 결과를 낼 때 벤치마크를 섞어 합산하지 않는다.

## 2. 왜 MalSkillBench를 주 데이터로 삼나

1단계(정적 분석)는 스크립트를 읽는다. 그런데 MaliciousSkillBench는 **정상 스킬에 스크립트 파일이 없다.** 악성 7,505개 중 4,918개는 스크립트가 있고 정상 2,235개는 전부 텍스트뿐이다. 이 상태로 1단계를 돌리면 "스크립트가 있다"는 사실만으로 악성을 맞히게 되어 성적이 부풀려진다. MalSkillBench와 SkillTrustBench는 정상 스킬에도 스크립트가 있어 스크립트 유무만으로 악성을 맞힐 수는 없다. 다만 MalSkillBench는 보유율 차이가 남아 있어 6절처럼 나눠 본다.

MalSkillBench가 더 맞는 이유가 둘 더 있다.
- **CI / PI / MIXED 라벨.** "1단계는 코드 공격(CI)을 잡고 2단계는 설명서 공격(PI)을 잡는가, MIXED는 둘 다 필요한가"가 우리 과제의 핵심 질문인데, 이 라벨이 그 질문의 정답 열이다. 벡터 라벨은 생성 3,214건에만 있고, 실제 730건(wild 703 + test 27)은 행동(B) 라벨만 있다.
- **실제 703건에 사람 검토 + 행동 라벨.** 실제 샘플만으로 잰 결과(논문 RQ2)와 나란히 놓을 수 있다.

SkillTrustBench는 **3등급 라벨** 때문에 쓴다. "취약(suspicious)을 악성과 분리할 때 성적이 어떻게 달라지나"를 여기서 잰다.

MaliciousSkillBench는 **기성 스캐너와의 비교** 때문에 쓴다. 논문이 Cisco, SkillFortify, SkillSpector를 Source-Disjoint 조건에서 잰 숫자가 있으므로, 우리 기준선을 같은 조건(SKILL.md 단일 사본, 사전 등록 게이트)으로 돌리면 그 옆에 놓을 수 있다. 이때는 우리 1단계도 `--skill-md-only`로 돌려야 공정하다.

## 3. manifest의 실제/합성 구분

| 벤치마크 | `real` | `synthetic` | `unknown` |
|---|---|---|---|
| MalSkillBench | 악성 730 (wild 703 + test 27), 정상 4,000 | 악성 3,214 (generated) | 0 |
| SkillTrustBench | 악성 244 (wild·wild_expanded·wild_diffused·external), 정상 1,502 (safe_pool 등)¹ | 악성 2,619 (injected*), 정상 1,155 (injected·injected_d8) | 0 |

¹ 정상은 이진 라벨 0 기준(normal + suspicious). 실제 정상 1,502에는 suspicious 12건(safe_pool 10, wild 2), 합성 정상 1,155에는 suspicious 1,002건이 들어 있다.
| MaliciousSkillBench | 악성 229 (wild), 정상 1,936 | 악성 3,850, 정상 299 | 악성 3,426 (mixed_unresolved) |

`safe_pool`(SkillTrustBench의 정상 씨앗 1,500개)은 장터에서 가져온 실제 스킬로 보고 `real`에 넣었다. 데이터 카드에 명시된 것은 아니므로, 결과에서 `origin` 열로 따로 걸러 볼 수 있게 원래 값을 보존했다.

## 4. 분할

`dataset × label × origin_group`으로 층화해서 `dev` 30% / `test` 70%, 시드 42. 규칙과 프롬프트는 `dev`에서만 고친다. `test`는 5주차에 한 번 본다.

MaliciousSkillBench에는 논문이 고정해 둔 분할(`random`, `source_disjoint` 등)이 따로 있다. 기성 스캐너와 비교할 때는 그 분할을 써야 하므로 `taxonomy` 열 안에 `source_disjoint`, `random` 값을 보존했다. GitHub README 원문: "Do not regenerate partitions."

## 5. 백신이 실제 악성 샘플을 지운다 (중요)

2026-09-26 새벽, 세 벤치마크를 `data/raw/`에 풀자 **Windows Defender 탐지 알림 120건(Get-MpThreatDetection, 한 알림이 여러 파일 포함)이 떴고 파일이 격리되었다** (탐지명 예: Trojan:Script/Wacatac.C!ml, Trojan:Python/MCCrash.B!MTB, VirTool:Python/Meterpreter.JA!MTB). 영향 받은 스킬은 919행이다(MalSkillBench 774 = 정상 84 + 실제 악성 597 + 생성 93, SkillTrustBench 65, MaliciousSkillBench 80). 지워진 것은 대부분 실제 유포 샘플이다. 원본 압축 파일 안에는 있다.

| 구분 | 원본 압축 파일 | 이 기계에 남은 것 |
|---|---|---|
| MalSkillBench 실제 악성 (wild 703 + test 27) | 730 | 133 |
| SkillTrustBench 실제 악성 | 244 | 179 |
| MaliciousSkillBench 실제 악성 (wild) | 229 | 197 |
| MalSkillBench 생성 악성 | 3,214 | 3,121 |
| MaliciousSkillBench 합성 악성 | 3,850 | 3,819 |
| MaliciousSkillBench unknown 악성 (mixed_unresolved) | 3,426 | 3,409 |

정상 스킬도 일부 지워졌다(MalSkillBench 정상 84건). 그래서 manifest에 `files_expected`(압축 파일 기준)와 `intact`(디스크 기준) 열을 두었다. 분할은 압축 파일 기준으로 정해 모두에게 같고, `intact = 0`인 행은 평가에서 자동으로 빠지면서 경고가 뜬다.

**해결은 팀이 정한다.** 선택지는 (1) 전용 폴더에 Defender 예외를 걸고 절대 실행하지 않기, (2) WSL2나 Docker, 별도 VM 안에서 데이터를 풀고 1단계를 돌리기, (3) 압축 파일에서 필요할 때만 메모리로 읽기(스캐너를 파일 대신 바이트로 돌리게 고침). 어느 쪽이든 **실제 악성 스크립트를 실행하지 않는다.** 기성 스캐너(Cisco 등)도 실행하지 않는다(정적 + LLM 판독). 첫 미팅 안건이다.

## 6. 알아 둘 것

- **Windows 파일 이름.** MalSkillBench 스킬 폴더 20여 개는 이름에 `:`가 들어 있어 Windows에서 만들 수 없다. `data/build_manifest.py`와 압축 해제 스크립트는 `:*?"<>|`를 `_`로 바꾼다. 원본 이름은 `_source_inventory.txt`에 있다.
- **21 MB 스킬.** MaliciousSkillBench에 SKILL.md가 21 MB인 샘플이 하나 있다(`ASB04_002434`, MalSkillBench 유래). 같은 파일이 MalSkillBench에는 `msb:klaviyoapi`(wild)로 들어 있다. MaliciousSkillBench 논문 부록 J.3이 이 파일을 Cisco 스캐너가 결과를 내지 못한 사례로 기록한다(Table 47: "no result (21 MB input)", 원문 "one roughly 21 MB input for which no result is produced"). 2026-09-26 원문 확인. 1단계는 2 MB 넘는 파일을 건너뛰고 `oversize`로 기록하고, 2단계는 앞 8,000자 + 뒤 4,000자만 넣는다.
- **재배포 금지.** `data/raw/`는 git에 올리지 않는다. 우리가 공개할 수 있는 것은 manifest(ID와 라벨), 예측 파일, 스크립트다. MaliciousSkillBench 문서 원문: 스킬 본문은 "retain their respective upstream terms".
- **스크립트 유무 편향.** 정상과 악성의 스크립트 보유율이 벤치마크마다 다르다. MalSkillBench 정상 19%(762/4,000) 대 악성 43%(1,703/3,944). 1단계 결과를 해석할 때 `has_script` 열로 나눠 본다.

## 7. 다시 만들기

```
# 1) 받기: docs/data.md 1절의 세 출처에서 data/raw/ 아래로 (build 스크립트의 docstring에 폴더 구조)
# 2) 압축 파일 기준 파일 수 (백신 격리 감지용)
python data/index_archives.py --malskillbench <tarball> --skilltrustbench <zip> --msb-packages <dir>
# 3) manifest
python data/build_manifest.py            # data/manifest.csv, data/manifest.sha256
```

`manifest.sha256`이 저장소의 값과 다르면 데이터가 다른 것이다. 결과 표에는 항상 이 해시 앞 8자리를 적는다.
