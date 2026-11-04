# "스크립트형" 판정: 악성 샘플 중 SKILL.md 말고 동봉 코드 파일(CODE_EXT 확장자 또는 #!)이 하나라도 있으면 스크립트형 (2026-11-04, E6 §8).
# 스크립트형을 뺀 나머지는 공격이 SKILL.md 글에 있을 수밖에 없는 샘플이다. 탐지기 결과는 쓰지 않는다. 위험 키워드 묶음은 기준 비교용(E6 §8).
# 압축은 풀지 않고 메모리에서 읽는다. 원문은 출력하지 않는다.
# 필요: package_manifest.csv, <SRC>_packages.tar.gz (MaliciousSkillBench packages/, SHA256SUMS.txt로 확인)
# 사용: cd data && python -I script_type.py <label이 있는 csv> <출력 csv>
#   dev: python -I script_type.py runs_dev/scores.csv runs_dev/script_type.csv
#   test(대표가 실행): 같은 스크립트를 test 목록과 그 출처 압축 파일로 그대로 돌린다
import os
import re
import sys
import tarfile

import pandas as pd

CODE_EXT = {".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".ts", ".ps1", ".psm1", ".bat", ".cmd",
            ".rb", ".pl", ".php", ".go", ".lua", ".pyc"}
GROUPS = {  # 동봉 코드 안의 위험 동작 키워드 묶음
    "net": r"requests\.(?:get|post|put)|urllib\.request|urlopen|http\.client|httpx|aiohttp|socket\.socket|\bfetch\(|axios"
           r"|XMLHttpRequest|\bcurl\s|\bwget\s|Invoke-WebRequest|Invoke-RestMethod|Net\.WebClient|\bnc\s+-",
    "exec": r"subprocess|os\.system|os\.popen|\beval\(|\bexec\(|child_process|execSync|\bspawn\(|Popen|Invoke-Expression"
            r"|\biex\b|\bbash\s+-c|\bsh\s+-c",
    "enc": r"base64|b64decode|\batob\(|fromCharCode|codecs\.decode|marshal\.loads|zlib\.decompress",
    "secret": r"\.ssh/|\.aws/|id_rsa|\.git-credentials|Login Data|keychain|/etc/passwd|os\.environ|process\.env|getenv",
    "persist": r"crontab|\.bashrc|\.zshrc|LaunchAgents|systemctl\s+enable|schtasks|CurrentVersion\\+Run",
}
GROUPS = {k: re.compile(v, re.I) for k, v in GROUPS.items()}


def is_code(name, head):
    return os.path.splitext(name)[1].lower() in CODE_EXT or head.startswith(b"#!")


def scan_archive(path, roots):
    """roots: 패키지 폴더(manifest package_relative_path) → benchmark_id.
    반환: benchmark_id → {'skill': 가장 얕은 SKILL.md 글, 'code': [(폴더 안 경로, 걸린 묶음 set)]}"""
    depths = {r.count("/") + 1 for r in roots}
    out, skill_depth = {}, {}
    with tarfile.open(path) as t:
        for mem in t:
            if not mem.isfile():
                continue
            parts = mem.name.split("/")
            root = next(("/".join(parts[:k]) for k in depths if "/".join(parts[:k]) in roots and len(parts) > k), None)
            if root is None:
                continue
            bid, rel = roots[root], "/".join(parts[root.count("/") + 1:])
            data = t.extractfile(mem).read()
            rec = out.setdefault(bid, {"skill": "", "code": []})
            if os.path.basename(rel).lower() == "skill.md":
                if rel.count("/") < skill_depth.get(bid, 99):  # 하위 폴더에 있으면 가장 얕은 것
                    rec["skill"], skill_depth[bid] = data.decode("utf-8", "ignore"), rel.count("/")
            elif is_code(rel, data[:2]):
                text = data.decode("utf-8", "ignore")
                rec["code"].append((rel, {k for k, p in GROUPS.items() if p.search(text)}))
    return out


def main():
    d = pd.read_csv(sys.argv[1])
    d = d[d.label == 1][["benchmark_id", "source_id"]]
    m = pd.read_csv("package_manifest.csv")[["benchmark_id", "package_archive", "package_relative_path"]]
    d = d.merge(m, on="benchmark_id", how="left")
    rows = []
    for arc, g in d.groupby("package_archive"):
        recs = scan_archive(arc, dict(zip(g.package_relative_path, g.benchmark_id)))
        for bid in g.benchmark_id:
            rec = recs.get(bid, {"skill": "", "code": []})
            named = [(n, gs) for n, gs in rec["code"] if os.path.basename(n) in rec["skill"]]
            union = lambda xs: set().union(*[gs for _, gs in xs]) if xs else set()
            rows.append({"benchmark_id": bid, "n_code": len(rec["code"]), "n_code_named": len(named),
                         "groups": " ".join(sorted(union(rec["code"]))), "groups_named": " ".join(sorted(union(named)))})
    out = d.merge(pd.DataFrame(rows), on="benchmark_id")
    out["script_type"] = (out.n_code > 0).astype(int)
    out.to_csv(sys.argv[2], index=False)
    print(f"악성 {len(out)}개 → {sys.argv[2]}. 스크립트형 {out.script_type.sum()}, 그중 SKILL.md가 이름을 부름 {(out.n_code_named > 0).sum()}")


if __name__ == "__main__":
    main()
