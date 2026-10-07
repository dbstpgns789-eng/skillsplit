# SkillGate·Cisco 공개 규칙을 받아 한 표(rules_all.csv)로 합친다. 한 행 = 정규식 하나.
# 받은 코드는 import하지 않는다(실행 안 함). ast·yaml로 리터럴만 읽는다.
import ast, csv, io, re, urllib.request, zipfile, yaml
from pathlib import Path

REPOS = {  # 버전 고정. 바꾸면 실험 기록(docs/experiments/)에 남긴다
    "skillgate": ("awsm-research/skillgate", "c1641c5d5664634296977ff7491f4cff469acfb7"),      # 2026-07-28
    "cisco": ("cisco-ai-defense/skill-scanner", "c3d7fd9fee50cf2ea45f0b381eb61f857360f825"),  # 2026-10-05
}
UP = Path("rules_upstream")

def fetch(name, repo, sha):
    d = UP / name
    if not d.exists():
        z = zipfile.ZipFile(io.BytesIO(urllib.request.urlopen(f"https://github.com/{repo}/archive/{sha}.zip").read()))
        z.extractall(UP)
        (UP / f"{repo.split('/')[1]}-{sha}").rename(d)
    return d

def tuples(path, var):  # ATTACK_PATTERNS 같은 튜플 리스트를 실행 없이 읽기
    for node in ast.parse(path.read_text(encoding="utf-8")).body:
        if isinstance(node, ast.AnnAssign) and node.target.id == var:
            for t in node.value.elts:
                yield [e.value if isinstance(e, ast.Constant) else e.attr for e in t.elts]

rows = []
sg = fetch("skillgate", *REPOS["skillgate"])
cls = sg / "skillgate/classifier"
for i, p, sev, desc, cat, mitre in tuples(cls / "attack_patterns.py", "ATTACK_PATTERNS"):
    rows.append(dict(source="skillgate", pack="attack", id=i, category=cat, severity=sev, pattern=p,
                     mitre=mitre or "", description=desc, flags="IM", license="MIT"))
for i, p, sev, desc, cat, mitre in tuples(cls / "sigma_patterns.py", "SIGMA_PATTERNS"):
    rows.append(dict(source="skillgate", pack="sigma", id=i, category=cat, severity=sev, pattern=p,
                     mitre=mitre or "", description=desc, flags="IM", license="DRL-1.1"))
for i, p in tuples(cls / "attack_patterns.py", "SAFE_PATTERNS"):  # 오탐 억제용
    rows.append(dict(source="skillgate", pack="safe", id=i, pattern=p, flags="IM", license="MIT"))
for f in ["default", "skills"]:
    for r in yaml.safe_load((sg / f"rules/{f}.yaml").read_text(encoding="utf-8"))["rules"]:
        rows.append(dict(source="skillgate", pack=f"yaml_{f}", id=r["id"], category=r.get("category", ""),
                         severity=r.get("severity", ""), pattern=r["pattern"], description=r.get("description", ""),
                         flags="IM", license="MIT"))

cs = fetch("cisco", *REPOS["cisco"])
for f in sorted((cs / "skill_scanner/data/packs").glob("*/signatures/*.yaml")):
    pack = f.parts[-3]
    data = yaml.safe_load(f.read_text(encoding="utf-8"))
    for r in data if isinstance(data, list) else data["signatures"]:
        for p in r.get("patterns", []):
            rows.append(dict(source="cisco", pack=pack, file=f.stem, id=r["id"], category=r.get("category", ""),
                             severity=r.get("severity", ""), pattern=p.strip(),
                             exclude=" || ".join(r.get("exclude_patterns", [])),
                             file_types=",".join(r.get("file_types", [])), description=r.get("description", ""),
                             flags="", license="MIT" if pack == "atr" else "Apache-2.0"))

for r in rows:  # 파이썬 re로 컴파일되는지 표시 (안 되면 dev 적중 계산에서 빠진다)
    try:
        re.compile(r["pattern"], (re.I | re.M) if r["flags"] else 0); r["compiles"] = 1
    except re.error:
        r["compiles"] = 0

cols = ["source", "pack", "file", "id", "category", "severity", "file_types", "flags", "pattern",
        "exclude", "mitre", "description", "license", "compiles"]
with open("rules_all.csv", "w", newline="", encoding="utf-8") as fp:
    w = csv.DictWriter(fp, cols, restval=""); w.writeheader(); w.writerows(rows)

print("정규식 행:", len(rows))
for (s, p) in sorted({(r["source"], r["pack"]) for r in rows}):
    sub = [r for r in rows if (r["source"], r["pack"]) == (s, p)]
    print(f"  {s}/{p}: 규칙 {len({r['id'] for r in sub})}, 정규식 {len(sub)}, 컴파일 실패 {sum(1 - r['compiles'] for r in sub)}")
