# SkillGate를 규칙만(LLM 끔) 켜고 스킬 폴더들을 스캔해 JSON으로 저장한다.
# CLI(skillgate scan)와 같은 함수를 부르되, 콘솔 표 대신 걸린 규칙 ID를 남긴다.
# 실행: .venv-skillgate/Scripts/python run_skillgate.py dev_skills runs_dev/skillgate.json
#
# 샘플당 시간 제한: 한 줄이 아주 긴 파일(dev의 ASB04_002434는 한 줄이 20MiB)에서는
# Sigma 규칙 (?=.*a)(?=.*b).* 가 줄 길이의 제곱으로 느려져 끝나지 않는다.
# 정규식은 중간에 끊을 수 없으므로 별도 프로세스에서 돌리고, 시간을 넘기면 죽이고 flag=None(스캔 실패)으로 남긴다.
import asyncio, json, sys
from multiprocessing import Pipe, Process
from pathlib import Path

TIMEOUT = 60  # 초. dev100에서 샘플당 1초 미만

def worker(conn):
    from skillgate.classifier.hybrid import create_classifier
    from skillgate.interceptor.response import ScanContext
    clf = create_classifier(use_llm=False)  # 논문 Table VI의 "규칙만" 조건
    while True:
        path = conn.recv()
        # CLI는 read_text()를 인코딩 없이 불러 Windows(cp949)에서 깨진다. 리눅스와 같게 utf-8로 읽는다
        r = asyncio.run(clf.classify(Path(path).read_text(encoding="utf-8"),
                                     ScanContext(tool_name="scan", upstream="local", source_path=path)))
        conn.send({"flag": int(not r.is_safe), "severity": r.severity.name if r.severity else None,
                   "rules": [m.rule.id for m in r.rule_matches]})

def start():
    a, b = Pipe()
    p = Process(target=worker, args=(b,), daemon=True); p.start()
    return p, a

if __name__ == "__main__":
    src, out = Path(sys.argv[1]), sys.argv[2]
    p, conn = start()
    res = []
    dirs = sorted(d for d in src.iterdir() if d.is_dir())
    for i, d in enumerate(dirs, 1):
        conn.send(str(d / "SKILL.md"))
        if conn.poll(TIMEOUT):
            res.append({"benchmark_id": d.name, **conn.recv()})
        else:
            p.kill(); p, conn = start()
            res.append({"benchmark_id": d.name, "flag": None, "severity": None, "rules": [], "error": f"timeout {TIMEOUT}s"})
            print("시간 초과:", d.name, flush=True)
        if i % 500 == 0:
            print(i, "/", len(dirs), flush=True)
    p.kill()
    json.dump(res, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("스캔:", len(res), "/ 걸림:", sum(x["flag"] or 0 for x in res), "/ 실패:", sum(x["flag"] is None for x in res))
