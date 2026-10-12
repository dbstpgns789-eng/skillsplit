# SRC001(MalSkillBench) 놓친 악성 분석: 패키지 파일 수별 놓친 비율 + 글 신호 집계. 원문은 출력하지 않는다.
# 필요: runs_dev/scores.csv(E1), package_manifest.csv(E3 재현 참고)
import re, pandas as pd

FENCE = re.compile(r"```.*?```", re.S)
R = {  # 산문(코드 블록 밖)에서 찾는다
    "marker": r"original\s+skill\.?\s*md",  # 생성기 경계 흔적. 탐지 규칙으로 쓰지 않는다
    "init_directive": r"(?:run|execute)\s+(?:the|this)\s+(?:following\s+)?initiali[sz]ation\s+(?:script|step|code|routine)"
                      r"|initiali[sz]ation\s+(?:script|step|routine)\s+(?:should|must)\s+be\s+(?:executed|run)"
                      r"|(?:before|prior to)\s+(?:beginning|starting|any)\b[^\n]{0,60}initiali[sz]",
    "operates_under": r"(?:skill|system|agent)\s+operates\s+(?:under|according to|with)\s+(?:the\s+)?following",
    "prompt_leak": r"(?:initial|original|system)\s+prompt\s+(?:was|is|reads|contents?)"
                   r"|(?:reveal|repeat|print|output|share|include)\s+(?:the\s+|your\s+)?(?:full\s+|complete\s+)?(?:system|initial)\s+(?:prompt|instructions)",
}
R = {k: re.compile(v, re.I) for k, v in R.items()}
H = re.compile(r"^#{1,4}\s+[^\n]*\b(?:operational|directives?|runtime\s+(?:configuration|profile|mode)|system\s+(?:initiali[sz]ation|configuration|directives?)"
               r"|execution\s+instructions|initiali[sz]ation)\b", re.I | re.M)

m = pd.read_csv("runs_dev/scores.csv")
m["miss"] = (m.cisco_any == 0) & (m.skillgate == 0)
m = m.merge(pd.read_csv("package_manifest.csv", usecols=["benchmark_id", "package_file_count"]), on="benchmark_id", how="left")

s = m[m.source_id == "SRC001"].copy()
s["files"] = pd.cut(s.package_file_count, [0, 1, 2, 5, 1000], labels=["1", "2", "3-5", "6+"])
t = s.groupby("files", observed=True).miss.agg(["sum", "count"]); t["rate"] = (t["sum"] / t["count"]).round(3)
print("== SRC001 패키지 파일 수별 놓친 비율\n" + t.to_string())

rows = []
for b in m.benchmark_id:
    t = open(f"dev_skills/{b}/SKILL.md", encoding="utf-8").read()[:300000]
    pr = FENCE.sub(" ", t)
    r = {k: bool(rx.search(pr)) for k, rx in R.items()}
    r["op_heading"] = bool(H.search(t))
    rows.append(r)
F = pd.DataFrame(rows, index=m.index); cols = list(F.columns)
m = pd.concat([m, F], axis=1)
gen = ["init_directive", "operates_under", "prompt_leak"]
s1 = m[m.source_id == "SRC001"]
out = pd.DataFrame({
    "SRC001 놓침": s1[s1.miss][cols].sum(), "SRC001 잡힘": s1[~s1.miss][cols].sum(),
    "다른 출처 악성": m[(m.label == 1) & (m.source_id != "SRC001")][cols].sum(), "정상": m[m.label == 0][cols].sum()})
print("\n== 신호별 샘플 수\n" + out.to_string())
x = s1[s1.miss]
rest = x[~x.marker & ~x[gen].any(axis=1)]
print(f"\n놓친 SRC001 {len(x)}: marker·지시 신호 모두 없음 {len(rest)}, 그중 op_heading {int(rest.op_heading.sum())}")
m[["benchmark_id"] + cols].to_csv("runs_dev/src001_signals.csv", index=False)
