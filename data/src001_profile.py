# SRC001 놓친 악성의 글 모양을 집계만으로 본다. 원문은 출력하지 않는다(소제목 이름만 출력).
# 사용: python src001_profile.py (data/에서). 결과는 E3 §3
import re, collections, pandas as pd
m = pd.read_csv("runs_dev/scores.csv")
m["miss"] = (m.cisco_any == 0) & (m.skillgate == 0)
p = pd.read_csv("package_manifest.csv", usecols=["benchmark_id", "package_file_count"])
m = m.merge(p, on="benchmark_id", how="left")
G = {
    "SRC001 놓침": m[(m.source_id == "SRC001") & m.miss],
    "SRC001 잡힘": m[(m.source_id == "SRC001") & ~m.miss],
    "정상(전체)": m[m.label == 0],
}
FENCE = re.compile(r"```([\w+-]*)[^\n]*\n(.*?)```", re.S)
HEAD = re.compile(r"^#{1,4}\s+(.+?)\s*$", re.M)
K = {
    "network": r"\b(?:requests\.(?:get|post)|urllib|fetch\(|axios|curl\b|wget\b|http\.client|socket\.|websocket)",
    "exec": r"\b(?:subprocess|os\.system|os\.popen|eval\(|exec\(|child_process|spawn\(|shell=True|Invoke-Expression|iex\b)",
    "sens_path": r"(?:~/\.ssh|id_rsa|\.aws/|\.env\b|credentials|\.npmrc|\.netrc|keychain|\.kube/config|\.gnupg|wallet|\.bash_history)",
    "env_read": r"\b(?:os\.environ|process\.env|getenv\(|\$\{?[A-Z_]*(?:KEY|TOKEN|SECRET|PASSWORD)\}?)",
    "encode": r"\b(?:base64|b64decode|b64encode|atob\(|btoa\(|fromCharCode|\\x[0-9a-f]{2})",
    "persist": r"(?:crontab|\.bashrc|\.zshrc|\.profile\b|launchd|LaunchAgents|systemd|autostart|startup folder|registry\\run)",
    "destroy": r"(?:rm\s+-rf|shutil\.rmtree|os\.remove|unlink\(|DROP\s+TABLE|format\s+c:)",
    "exfil_sink": r"(?:webhook|discord(?:app)?\.com/api|api\.telegram\.org|pastebin|ngrok|requestbin|transfer\.sh|\.onion\b)",
    "agent_ctl": r"(?:ignore (?:all |any )?(?:previous|prior)|system prompt|do not (?:tell|inform|mention)|without (?:asking|confirmation|telling)|you are now|override)",
    "auto_approve": r"(?:auto[- ]?approve|--yes\b|-y\b|--force\b|--no-verify|dangerously|bypassPermissions|skip(?:ping)? confirmation)",
}
K = {k: re.compile(v, re.I) for k, v in K.items()}

def prof(t):
    fences = FENCE.findall(t)
    code = "\n".join(b for _, b in fences)
    prose = FENCE.sub(" ", t)
    r = {"len": len(t), "n_fence": len(fences), "langs": [l.lower() or "(none)" for l, _ in fences],
         "heads": [h.strip().lower()[:50] for h in HEAD.findall(prose)]}
    for k, rx in K.items():
        r["code_" + k] = bool(rx.search(code))
        r["prose_" + k] = bool(rx.search(prose))
    return r

rows = {}
for g, d in G.items():
    P = [prof(open(f"dev_skills/{b}/SKILL.md", encoding="utf-8").read()[:300000]) for b in d.benchmark_id]
    rows[g] = P

print("== 크기, 코드 블록")
for g, P in rows.items():
    s = pd.Series([x["len"] for x in P]); nf = pd.Series([x["n_fence"] for x in P])
    print(f"{g:10s} n={len(P):5d} 길이 중앙값 {int(s.median()):6d}  코드블록 0개 비율 {(nf==0).mean():.2f}  코드블록 중앙값 {int(nf.median())}")
print("\n== 키워드 계열: 해당 샘플 비율 (code / prose)")
keys = list(K)
t = pd.DataFrame({g: {k: f"{pd.Series([x['code_'+k] for x in P]).mean():.2f} / {pd.Series([x['prose_'+k] for x in P]).mean():.2f}" for k in keys} for g, P in rows.items()})
print(t.to_string())
print("\n== 아무 키워드도 없는 비율")
for g, P in rows.items():
    print(g, round(pd.Series([not any(x['code_'+k] or x['prose_'+k] for k in keys) for x in P]).mean(), 3))
print("\n== 코드 블록 언어 상위")
for g, P in rows.items():
    c = collections.Counter(l for x in P for l in set(x["langs"])); print(g, [(l, round(n/len(P), 2)) for l, n in c.most_common(8)])
print("\n== 소제목: SRC001 놓침에서 자주 나오고 정상에서 드문 것 (문서 비율)")
def hf(P): return collections.Counter(h for x in P for h in set(x["heads"]))
a, b, n_a, n_b = hf(rows["SRC001 놓침"]), hf(rows["정상(전체)"]), len(rows["SRC001 놓침"]), len(rows["정상(전체)"])
sc = sorted(((ca / n_a, (b[h] + 1) / n_b, h) for h, ca in a.items() if ca >= 8), key=lambda x: -x[0] / x[1])
for ra, rb, h in sc[:25]:
    print(f"  {ra:.3f} vs {rb:.3f}  {h}")
