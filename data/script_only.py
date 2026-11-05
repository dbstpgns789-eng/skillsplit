# script-only 판정 1단계(자동): 악성 샘플마다 동봉 코드 파일에서 공격 동작 근거를 찾아 "파일:줄:동작"으로 남긴다.
# 2단계(사람): 근거가 있는 샘플만 SKILL.md 본문을 E4 기준표로 판정 → text_attack / script_only / unclear (초안, E6 §8).
# 탐지기 결과는 쓰지 않는다. 압축은 풀지 않고 메모리에서 읽는다. 원문은 출력하지 않는다.
# 필요: package_manifest.csv, <SRC>_packages.tar.gz (MaliciousSkillBench packages/, SHA256SUMS.txt로 확인)
# 사용: cd data && python -I script_only.py <benchmark_id·label 열이 있는 csv> <출력 csv>
#   dev: python -I script_only.py runs_dev/scores.csv runs_dev/script_evidence.csv
import os
import re
import sys
import tarfile

import pandas as pd

CODE_EXT = {".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".ts", ".ps1", ".psm1", ".bat", ".cmd",
            ".rb", ".pl", ".php", ".go", ".lua", ".pyc"}
# 공격 동작 근거. 한 줄 안에서 보는 강한 형태만 둔다(단순한 네트워크 호출·환경변수 읽기·subprocess는 정상 스크립트에도 흔해서 뺌)
EVIDENCE = {
    "DL_EXEC": r"\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|\b(?:exec|eval)\s*\(\s*(?:requests\.get|urlopen|urllib\.request\.urlopen|httpx\.get)"
               r"|\b(?:iex|Invoke-Expression)\b[^\n]{0,100}\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod|DownloadString)\b"
               r"|\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n]{0,200}\|\s*(?:iex|Invoke-Expression)\b",
    "OBF_EXEC": r"\b(?:exec|eval)\s*\([^\n]{0,200}\b(?:b64decode|atob|fromCharCode|codecs\.decode|zlib\.decompress|marshal\.loads)\b"
                r"|\bbase64\s+(?:-d|--decode)\b[^\n]{0,100}\|\s*(?:ba|z)?sh\b|\bnew\s+Function\s*\([^\n]{0,100}\batob\b",
    "SECRET_READ": r"[/\\]\.ssh[/\\](?:id_\w+|authorized_keys)|\.aws[/\\]credentials|\.git-credentials|Login Data|Library/Keychains"
                   r"|\bsecurity\s+(?:dump-keychain|find-generic-password)\b|/etc/shadow|wallet\.dat|\.docker/config\.json|\.npmrc|\.pypirc",
    "ENV_DUMP": r"dict\(\s*os\.environ\s*\)|os\.environ\.copy\(\)|json\.dumps\(\s*(?:dict\()?os\.environ|JSON\.stringify\(\s*process\.env\s*\)"
                r"|\bprintenv\b|\benv\s*\|",
    "EXFIL_ENDPOINT": r"discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot|hooks\.slack\.com/services|webhook\.site|requestbin|ngrok\.io"
                      r"|pastebin\.com/api|\b(?:nc|ncat|netcat)\b[^\n]{0,60}\d{2,5}\s*<|https?://(?!127\.|0\.0\.0\.0|10\.|192\.168\.)\d{1,3}(?:\.\d{1,3}){3}",  # 로컬·사설 IP는 뺌
    "PERSIST": r"\(\s*crontab\s+-l|\bcrontab\s+-e\b|>>\s*~?/?\S*\.(?:bashrc|zshrc|bash_profile|profile)\b|LaunchAgents/|\blaunchctl\s+load\b"
               r"|\bsystemctl\s+(?:--user\s+)?enable\b|\bschtasks\b|CurrentVersion\\+Run",
}
EVIDENCE = {k: re.compile(v, re.I) for k, v in EVIDENCE.items()}


def is_code(name, head):
    return os.path.splitext(name)[1].lower() in CODE_EXT or head.startswith(b"#!")


def evidence(text):
    """[(동작, 줄 번호)] 동작마다 처음 걸린 줄."""
    out = []
    for k, p in EVIDENCE.items():
        m = p.search(text)
        if m:
            out.append((k, text.count("\n", 0, m.start()) + 1))
    return out


def scan_archive(path, roots):
    """roots: 패키지 폴더(manifest package_relative_path) → benchmark_id.
    반환: benchmark_id → {'skill': 가장 얕은 SKILL.md 글, 'n_code': 코드 파일 수, 'ev': [(폴더 안 경로, 동작, 줄)]}"""
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
            rec = out.setdefault(bid, {"skill": "", "n_code": 0, "ev": []})
            if os.path.basename(rel).lower() == "skill.md":
                if rel.count("/") < skill_depth.get(bid, 99):  # 하위 폴더에 있으면 가장 얕은 것
                    rec["skill"], skill_depth[bid] = data.decode("utf-8", "ignore"), rel.count("/")
            elif is_code(rel, data[:2]):
                rec["n_code"] += 1
                rec["ev"] += [(rel, k, ln) for k, ln in evidence(data.decode("utf-8", "ignore"))]
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
            rec = recs.get(bid, {"skill": "", "n_code": 0, "ev": []})
            named = {rel for rel, _, _ in rec["ev"] if os.path.basename(rel) in rec["skill"]}
            rows.append({"benchmark_id": bid, "n_code": rec["n_code"], "code_evidence": len(rec["ev"]) > 0,
                         "evidence_named": len(named) > 0,  # 근거가 있는 파일을 SKILL.md가 이름으로 부름
                         "behaviors": " ".join(sorted({k for _, k, _ in rec["ev"]})),
                         "evidence": "; ".join(f"{rel}:{ln}:{k}" for rel, k, ln in rec["ev"])})
    out = d.drop(columns=["package_archive", "package_relative_path"]).merge(pd.DataFrame(rows), on="benchmark_id")
    out.to_csv(sys.argv[2], index=False)
    print(f"악성 {len(out)} → {sys.argv[2]}: 코드 파일 있음 {(out.n_code > 0).sum()}, 코드 근거 있음 {out.code_evidence.sum()}, "
          f"그중 SKILL.md가 그 파일을 부름 {out.evidence_named.sum()}")


if __name__ == "__main__":
    main()
