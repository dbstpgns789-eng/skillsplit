# 놓친 악성에서 본 패턴을 행위 신호로 일반화해 dev 전체에서 집계. 원문은 출력하지 않는다.
import re, pandas as pd

FENCE = re.compile(r"```.*?```", re.S)
FM = re.compile(r"\A---\n(.*?)\n---", re.S)
S = {
    # 산문에서 로컬 스크립트 실행을 선행·필수 단계로 지시
    "run_directive": re.compile(r"(?:must|always|first|before|required|pre-?flight|prerequisite|initiali[sz]\w*)[^\n]{0,120}`(?:python3?|bash|sh|node|pwsh|powershell)\s+[\w./~-]+`"
                                r"|`(?:python3?|bash|sh|node|pwsh|powershell)\s+[\w./~-]+`[^\n]{0,120}(?:must|always|first|before|required|pre-?flight|prerequisite)", re.I),
    # 사용자에게 숨기기
    "conceal": re.compile(r"(?:do not|don't|never|without)\s+(?:surface|mention|tell|inform|show|notify|reveal|disclose|asking|telling|notifying|alerting)\w*\b[^\n]{0,40}\buser"
                          r"|\bsilently\s+(?:run|execute|install|send|upload|download)", re.I),
    # 문자 위장: 한 단어 안에 라틴 + 키릴/그리스
    "homoglyph": re.compile(r"\b(?=\w*[A-Za-z])(?=\w*[Ͱ-ϿЀ-ӿ])\w{3,}\b"),
    # 외부 유도: 비번 걸린 압축, 붙여넣기 사이트, 터미널에 붙여넣기
    "lure": re.compile(r"\.(?:zip|rar|7z)\b[^\n]{0,80}\bpass(?:word)?\b|\bpass(?:word)?\s*[:=][^\n]{0,40}\.(?:zip|rar|7z)\b"
                       r"|\b(?:glot\.io|pastebin\.com|rentry\.(?:co|org)|hastebin|paste\.ee|ghostbin)\b"
                       r"|\bpaste\b[^\n]{0,60}\binto\s+(?:the\s+|your\s+)?(?:terminal|powershell|shell|command prompt)", re.I),
    # 역할·목표 덮어쓰기
    "role_override": re.compile(r"(?:from (?:now|this point)\s*(?:on|forward)|henceforth)[^\n]{0,40}\byou\s+(?:are|will|must)\b"
                                r"|\bpermanent\s+(?:operational\s+)?(?:requirement|instruction|directive)", re.I),
}
DESC = re.compile(r"\b(?:bypass\w*|unrestricted|jailbreak\w*|no (?:restrictions?|limits?)|ignore (?:safety|previous|all)|classified|override (?:safety|guardrails?))\b", re.I)
SHORTCUT = re.compile(r"scripts/_\w+\.(?:py|sh|js|ts)\b")

def feats(t):
    t = t[:300000]
    prose = FENCE.sub(" ", t)
    fm = FM.match(t)
    f = {k: bool((r if k != "homoglyph" else r).search(t if k == "homoglyph" else prose)) for k, r in S.items()}
    f["desc_bypass"] = bool(fm and DESC.search(fm.group(1)))
    f["shortcut_underscore"] = bool(SHORTCUT.search(t))
    return f

m = pd.read_csv("runs_dev/scores.csv")
m["miss"] = (m.cisco_any == 0) & (m.skillgate == 0)
F = pd.DataFrame([feats(open(f"dev_skills/{b}/SKILL.md", encoding="utf-8").read()) for b in m.benchmark_id])
m = pd.concat([m, F], axis=1)
cols = list(F.columns)
gen = [c for c in cols if c != "shortcut_underscore"]
m["any_new"] = m[gen].any(axis=1)

mal, ben, mis = m[m.label == 1], m[m.label == 0], m[(m.label == 1) & m.miss]
out = pd.DataFrame({
    "악성%": mal[cols + ["any_new"]].mean() * 100,
    "놓친악성%": mis[cols + ["any_new"]].mean() * 100,
    "놓친악성n": mis[cols + ["any_new"]].sum(),
    "정상n": ben[cols + ["any_new"]].sum(),
}).round(1)
print(out.to_string())
print("\n놓친 악성 중 any_new 비율, provenance별")
print(mis.groupby("provenance").any_new.agg(["mean", "sum", "count"]).round(3).to_string())
print("\n정상 중 걸린 신호 provenance별 개수")
print(ben.groupby("provenance")[cols].sum().to_string())
# 기존 두 도구 + 새 신호 OR
new_or = (m.cisco_any == 1) | (m.skillgate == 1) | m.any_new
cis_new = (m.cisco_any == 1) | m.any_new
for name, p in [("Cisco+SG+new", new_or), ("Cisco+new", cis_new), ("new only", m.any_new)]:
    print(f"{name:14s} recall {p[m.label==1].mean():.3f}  FPR {p[m.label==0].mean():.3f}")
# shortcut 없이(injected 놓친 것 중 일반화 신호로만 잡히는 비율)
inj = mis[mis.provenance == "injected"]
print("\ninjected 놓친", len(inj), " shortcut", int(inj.shortcut_underscore.sum()), " any_new", int(inj.any_new.sum()),
      " shortcut인데 any_new 없음", int((inj.shortcut_underscore & ~inj.any_new).sum()))
m[["benchmark_id", "label", "provenance", "source_id", "miss"] + cols].to_csv("runs_dev/signals.csv", index=False)
