"""스킬 폴더가 data/skills.csv 원문과 바이트까지 같은지 확인하고, ID 목록의 해시를 낸다. 라벨은 읽지 않는다.

  python -m skillsplit.stage2.check_dataset data/dev_skills

Windows Defender가 악성 SKILL.md를 막으면 폴더는 남고 읽기만 실패한다(E1 §5, stage2-log 2026-11-04). 그래서 실행 전에 확인한다.
"""
import csv
import hashlib
import sys
from pathlib import Path


def main():
    root = Path(sys.argv[1])
    ids = sorted(p.name for p in root.iterdir() if p.is_dir())
    wanted = set(ids)
    csv.field_size_limit(10**9)
    original = {}
    with open("data/skills.csv", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            if row["benchmark_id"] in wanted:
                original[row["benchmark_id"]] = row["skill_text"] or ""
    unreadable, different, digest = [], [], hashlib.sha256()
    for skill_id in ids:
        try:
            data = (root / skill_id / "SKILL.md").read_bytes()
        except OSError:
            unreadable.append(skill_id)
            continue
        if skill_id not in original or data != original[skill_id].encode("utf-8"):
            different.append(skill_id)
        digest.update(hashlib.sha256(data).digest())
    print(f"폴더 {len(ids):,}개, skills.csv에 없음 {len(wanted - set(original))}, 읽기 실패 {len(unreadable)}, 원문과 다름 {len(different)}")
    print("ID 목록 sha256:", hashlib.sha256("\n".join(ids).encode()).hexdigest())
    print("SKILL.md 전체 sha256(ID 순서):", digest.hexdigest())
    if unreadable or different:
        print("문제 ID(앞 20개):", (unreadable + different)[:20])
        raise SystemExit(1)


if __name__ == "__main__":
    main()
