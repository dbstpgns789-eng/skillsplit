# SRC001 놓친 악성에서 정상 대비 특징적인 3단어 어구만 출력. 원문 줄은 출력하지 않는다.
import re, collections, math, ast, pandas as pd
m = pd.read_csv("runs_dev/scores.csv")
m["miss"] = (m.cisco_any == 0) & (m.skillgate == 0)
FENCE = re.compile(r"```.*?```", re.S)
URL = re.compile(r"\S+://\S+|\b[\w-]+\.(?:com|io|net|org|sh|app|dev|xyz)\b\S*")
W = re.compile(r"[a-z][a-z'-]+")
STOP = set("the a an and or of to in for on with is are be this that it as by at from your you".split())

def grams(t):
    t = URL.sub(" ", FENCE.sub(" ", t[:300000]).lower())
    w = [x for x in W.findall(t)]
    return {" ".join(w[i:i+3]) for i in range(len(w) - 2) if sum(x in STOP for x in w[i:i+3]) < 2}

def df(ids):
    c = collections.Counter()
    for b in ids:
        c.update(grams(open(f"dev_skills/{b}/SKILL.md", encoding="utf-8").read()))
    return c

ben = m[m.label == 0]; B = df(ben.benchmark_id); nb = len(ben)
s = m[(m.source_id == "SRC001") & m.miss].copy()
s["cats"] = s.attack_category_codes.fillna("[]").str.replace("\n", " ").str.replace("' '", "', '").map(ast.literal_eval)
groups = {"전체": s}
for c in ["instruction_goal_memory_manipulation", "execution_code_delivery", "resource_availability_abuse",
          "data_exfiltration_disclosure", "credential_access"]:
    groups[c] = s[s.cats.map(lambda x: x == [c])]
groups["(카테고리 없음)"] = s[s.cats.map(len) == 0]
for g, d in groups.items():
    A = df(d.benchmark_id); na = len(d)
    sc = [(A[k] / na, B[k] / nb, k) for k in A if A[k] >= max(4, 0.03 * na)]
    sc.sort(key=lambda x: -(x[0] * math.log((x[0] + 1e-3) / (x[1] + 1e-3))))
    print(f"\n== {g} (n={na})")
    for ra, rb, k in sc[:14]:
        print(f"  {ra:.2f} vs 정상 {rb:.3f}  {k}")
