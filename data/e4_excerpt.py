# E4: 판정용 짧은 발췌. 539개에서 seed 0으로 50개를 뽑고, 샘플마다 소제목 목록과 발췌만 보여 준다.
# 에이전트·지시 관련 단어가 많은 문장 5개를 보여 주고, 바탕 글을 공유하는 샘플(e4_pairs.csv)이 있으면 그 샘플에 없는 문단도 보여 준다.
# URL·코드·명령은 가리고 한 조각을 200자로 자른다(원문 전체를 출력하지 않는다).
# 사용: python e4_excerpt.py <시작> <끝>   (표본 순번, 예: 0 10) → runs_dev/e4_sample.csv
import re, sys, pandas as pd

def defang(s):
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

r = pd.read_csv("runs_dev/e4_residual.csv").sample(50, random_state=0).reset_index(drop=True)
r.to_csv("runs_dev/e4_sample.csv", index=False)
pairs = pd.read_csv("runs_dev/e4_pairs.csv").set_index("benchmark_id")
meta = pd.read_csv("runs_dev/scores.csv").set_index("benchmark_id")

def paras(b):
    t = open(f"dev_skills/{b}/SKILL.md", encoding="utf-8").read()[:300000]
    return t, [p for p in re.split(r"\n\s*\n", t) if len(re.sub(r"\s+", " ", p).strip()) >= 40]

norm = lambda p: re.sub(r"\s+", " ", p).strip().lower()
a, z = int(sys.argv[1]), int(sys.argv[2])
for i, b in enumerate(r.benchmark_id[a:z], a):
    t, ps = paras(b)
    heads = [defang(h)[:50] for h in re.findall(r"^#{1,3}\s+(.+)$", t, re.M)]
    print(f"\n### [{i}] {b} | {meta.attack_category_codes[b]} | {len(t)}자 | 소제목 {len(heads)}개")
    print("  소제목:", " / ".join(heads[:25]))
    prose = re.sub(r"```.*?```", " ", t, flags=re.S)
    ss = [x for x in re.split(r"(?<=[.!?])\s+|\n", prose) if len(x) > 30 and not x.lstrip().startswith("|")]
    top = sorted(ss, key=lambda x: -(2 * len(A.findall(x)) + len(W.findall(x))))[:5]
    print("  에이전트·지시 관련 문장:")
    for x in top:
        print("   -", defang(x))
    if b in pairs.index:
        ref = pairs.ref[b]
        rs = {norm(p) for p in paras(ref)[1]}
        add = [p for p in ps if norm(p) not in rs]
        print(f"  기준 {ref}(잡힘={pairs.ref_caught[b]}) 대비 추가 문단 {len(add)}개:")
        for p in add[:4]:
            print("   +", defang(p))
