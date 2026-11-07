# 작은 출처 미탐 사례 판정용 발췌(E6 §5). 정적 v1이 놓친 악성(score 0)에서 출처마다 seed 0으로 N개를 뽑는다.
# 샘플마다 E4와 같은 방식(소제목, 에이전트·지시 관련 문장 5개, URL·코드·명령 가림, 200자)으로 SKILL.md를 보여 주고,
# 동봉 코드 파일은 원문 없이 이름·SKILL.md가 부르는지·자동 근거(script_only.py)·키워드 묶음·URL 수만 보여 준다.
# 사용: cd data && python -I case_excerpt.py <시작> <끝>  → runs_dev/small_src_sample.csv (표본 목록)
import os
import re
import sys
import tarfile

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # -I는 스크립트 폴더를 import 경로에서 빼므로 직접 넣는다
from script_only import evidence, is_code


def defang(s):  # e4_excerpt.py와 같음 (그 파일은 import하면 표본 뽑기가 실행돼서 복사)
    s = re.sub(r"```.*?```", " [CODE] ", s, flags=re.S)
    s = re.sub(r"`[^`\n]*`", "[CMD]", s)
    s = re.sub(r"(?:https?://|www\.)\S+|\b[\w.-]+\.(?:com|net|org|io|sh|ru|xyz|app|dev)\b\S*", "[URL]", s)
    s = re.sub(r"\b[A-Za-z0-9+/=]{40,}\b", "[B64]", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s[:200]


A = re.compile(r"\b(assistant|agent|the ai|claude|model|llm|system prompt|instructions?|prompt|directive|operator|users?|"
               r"credentials?|tokens?|api keys?|environment variables?|passwords?|monitor\w*|telemetry|"
               r"before (?:any|proceeding|beginning|starting)|initiali[sz]\w*)\b", re.I)
W = re.compile(r"\b(always|never|must|do not|don't|without|automatically|all|every|ignore|override|instead|secret\w*|silent\w*|"
               r"priorit\w*|record|log|collect|send|upload|share|retain|store|disclos\w*|bypass|unrestrict\w*|regardless)\b", re.I)

SOURCES = ["SRC004", "SRC005", "SRC006", "SRC013"]
N = 10
KEYS = {"net": r"requests\.|urllib|urlopen|http\.client|httpx|socket|fetch\(|axios|curl\s|wget\s|Invoke-WebRequest",
        "exec": r"subprocess|os\.system|os\.popen|\beval\(|\bexec\(|child_process|spawn\(|Popen",
        "enc": r"base64|b64decode|atob\(|fromCharCode|zlib|marshal",
        "secret": r"\.ssh|\.aws|credential|password|token|os\.environ|process\.env|getenv|keychain",
        "file": r"open\(|readFile|os\.walk|glob\.|Path\.home|expanduser|shutil"}
KEYS = {k: re.compile(v, re.I) for k, v in KEYS.items()}
URL = re.compile(r"https?://([\w.-]+)", re.I)


def code_info(x):
    """원문 대신: 자동 근거, 걸린 키워드 토큰(최대 8), URL 호스트(점을 [.]로 가림)."""
    toks = sorted({m.group(0).strip().lower() for p in KEYS.values() for m in p.finditer(x)})[:8]
    hosts = sorted({h.lower().replace(".", "[.]") for h in URL.findall(x)})[:5]
    return f"근거={','.join(k for k, _ in evidence(x)) or '-'} 토큰={','.join(toks) or '-'} URL호스트={','.join(hosts) or '-'}"


def sample():
    d = pd.read_csv("runs_dev/s1_v1_samples.csv")
    miss = d[(d.label == 1) & (d.score == 0) & d.source_id.isin(SOURCES)]
    s = pd.concat([g.sample(min(N, len(g)), random_state=0) for _, g in miss.groupby("source_id")]).reset_index(drop=True)
    m = pd.read_csv("package_manifest.csv")[["benchmark_id", "package_archive", "package_relative_path"]]
    return s[["benchmark_id", "source_id", "attack_category_codes"]].merge(m, on="benchmark_id", how="left")


def code_files(arc, root, skill):
    out = []
    with tarfile.open(arc) as t:
        for mem in t:
            if mem.isfile() and mem.name.startswith(root + "/"):
                rel = mem.name[len(root) + 1:]
                data = t.extractfile(mem).read()
                if os.path.basename(rel).lower() != "skill.md" and is_code(rel, data[:2]):
                    x = data.decode("utf-8", "ignore")
                    out.append(f"{os.path.basename(rel)}{' (SKILL.md가 부름)' if os.path.basename(rel) in skill else ''} "
                               f"줄={x.count(chr(10)) + 1} {code_info(x)}")
    return out


def main():
    s = sample()
    s.to_csv("runs_dev/small_src_sample.csv", index=False)
    a, z = int(sys.argv[1]), int(sys.argv[2])
    for i, r in s.iloc[a:z].iterrows():
        t = open(f"dev_skills/{r.benchmark_id}/SKILL.md", encoding="utf-8").read()[:300000]
        heads = [defang(h)[:50] for h in re.findall(r"^#{1,3}\s+(.+)$", t, re.M)]
        print(f"\n### [{i}] {r.benchmark_id} {r.source_id} | {r.attack_category_codes} | {len(t)}자 | 소제목 {len(heads)}개")
        print("  소제목:", " / ".join(heads[:25]))
        prose = re.sub(r"```.*?```", " ", t, flags=re.S)
        ss = [x for x in re.split(r"(?<=[.!?])\s+|\n", prose) if len(x) > 30 and not x.lstrip().startswith("|")]
        for x in sorted(ss, key=lambda x: -(2 * len(A.findall(x)) + len(W.findall(x))))[:5]:
            print("   -", defang(x))
        blocks = "\n".join(re.findall(r"```[^\n]*\n(.*?)```", t, flags=re.S))
        print(f"  SKILL.md 코드 블록 {len(re.findall(r'```', t)) // 2}개: {code_info(blocks)}")
        if isinstance(r.package_archive, str):
            for c in code_files(r.package_archive, r.package_relative_path, t):
                print("   ·", c)


if __name__ == "__main__":
    main()
