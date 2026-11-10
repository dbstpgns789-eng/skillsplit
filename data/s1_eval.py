# 정적 탐지기 결과 집계 (dev·test 공용). 입력 확인 → 결과 확인 → 재현율·오탐률(분자/분모), 출처별, script-only 제외.
# 걸림 기준: score > 0 (규칙이 하나라도 발동하면 걸림. 결합 전용 규칙은 짝이 있어야 발동). 원문은 출력하지 않는다.
# 사용: cd data && python s1_eval.py <스킬 폴더> <결과 .jsonl> <정답 csv: benchmark_id,label,source_id> [--script-only <csv: benchmark_id,verdict>]
#   dev:  python s1_eval.py dev_skills ../runs/stage1_v1_dev.jsonl runs_dev/scores.csv
#   test: python s1_eval.py test_skills ../runs/stage1_v1_test.jsonl <test 정답 csv> [--script-only <확정된 분류 csv>]
import argparse
import hashlib
import json
from pathlib import Path

import pandas as pd


def frac(a, b):
    return f"{a}/{b} = {a / b:.3f}" if b else f"{a}/0"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("skills_root")
    ap.add_argument("results")
    ap.add_argument("labels")
    ap.add_argument("--script-only", help="script-only 분류(verdict 열: text_attack / script_only / unclear). script_only만 뺀다")
    ap.add_argument("--skills-csv", default="skills.csv", help="원문 해시 확인용 (skill_text의 sha256 = 파일의 sha256)")
    a = ap.parse_args()

    lab = pd.read_csv(a.labels)
    if "source_id" not in lab:  # dev100_labels.csv처럼 출처 열이 없으면 skills.csv에서
        lab = lab.merge(pd.read_csv(a.skills_csv, usecols=["benchmark_id", "source_id"]), on="benchmark_id")
    lab = lab[["benchmark_id", "label", "source_id"]]
    ids = set(lab.benchmark_id)
    print(f"== 입력: 정답 {len(lab)}개 (악성 {(lab.label == 1).sum()}, 정상 {(lab.label == 0).sum()})")
    files = {p.parent.name: p for p in Path(a.skills_root).glob("*/SKILL.md")}
    print(f"SKILL.md 파일 {len(files)}개, 정답에 있는데 파일 없음 {len(ids - set(files))}, 정답에 없는 파일 {len(set(files) - ids)}")
    text = pd.read_csv(a.skills_csv, usecols=["benchmark_id", "skill_text"]).set_index("benchmark_id").skill_text.fillna("")
    sha = lambda b: hashlib.sha256(b).hexdigest()
    crlf, bad = [], []
    for b in sorted(ids & set(files)):
        raw, want = files[b].read_bytes(), text.get(b, "").encode("utf-8")
        if sha(raw) != sha(want):
            # 줄바꿈만 CRLF로 바뀐 사본은 read_skill(read_text)이 LF로 읽으므로 탐지기 입력은 같다
            (crlf if raw.replace(b"\r\n", b"\n") == want else bad).append(b)
    print(f"원문 sha256 일치 {len(ids & set(files)) - len(crlf) - len(bad)}, 줄바꿈(CRLF)만 다름 {len(crlf)}, 불일치 {len(bad)}{' ' + str(bad[:10]) if bad else ''}")

    rows = [json.loads(l) for l in open(a.results, encoding="utf-8") if l.strip()]
    r = pd.DataFrame(rows)
    print(f"\n== 결과: {len(r)}줄, 중복 id {r.skill_id.duplicated().sum()}, 누락 {len(ids - set(r.skill_id))}, 정답에 없는 id {len(set(r.skill_id) - ids)}")
    det = Path(a.results).with_suffix(".details.jsonl")
    if det.exists():
        dd = pd.DataFrame([json.loads(l) for l in open(det, encoding="utf-8") if l.strip()])
        print(f"details: 200,000자 초과(oversize) {int(dd.oversize.sum())}, 앞 300,000자만 검사 {int((dd.scanned_chars == 300_000).sum())}, 빈 SKILL.md {int(dd['empty'].sum())}")
    print("실행 실패: 정적은 실패 처리가 없다(모든 스킬에 점수를 냄). 누락이 0이면 실패 0")

    d = lab.merge(r.drop_duplicates("skill_id").rename(columns={"skill_id": "benchmark_id"}), on="benchmark_id", how="left")
    d["hit"] = d.score.fillna(0) > 0

    def report(x, name):
        mal, ben = x[x.label == 1], x[x.label == 0]
        print(f"{name}: 재현율 {frac(int(mal.hit.sum()), len(mal))}, 오탐률 {frac(int(ben.hit.sum()), len(ben))}")
        t = x.groupby("source_id").apply(lambda g: pd.Series({
            "악성 걸림/악성": f"{int(g[g.label == 1].hit.sum())}/{(g.label == 1).sum()}",
            "정상 걸림/정상": f"{int(g[g.label == 0].hit.sum())}/{(g.label == 0).sum()}"}))
        print(t.to_string())

    print("\n== 전체 기준")
    report(d, "전체")
    if a.script_only:
        so = pd.read_csv(a.script_only)[["benchmark_id", "verdict"]]
        d = d.merge(so, on="benchmark_id", how="left")
        mal = d.label == 1
        print(f"\n== script-only 제외 기준: 분류된 악성 {int(d[mal].verdict.notna().sum())}개 중 "
              f"script_only {int((d[mal].verdict == 'script_only').sum())}, unclear {int((d[mal].verdict == 'unclear').sum())}(남김), "
              f"text_attack {int((d[mal].verdict == 'text_attack').sum())}")
        report(d[~(mal & (d.verdict == "script_only"))], "script-only 제외")


if __name__ == "__main__":
    main()
