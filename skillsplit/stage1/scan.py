"""1단계 정적 탐지기 v0: SKILL.md를 영역별로 나눠 규칙을 적용하고 noisy-OR 점수를 낸다.

  python -m skillsplit.stage1.scan data/dev100 --out runs/stage1_v0_dev100.jsonl
"""
import bisect
import re

from .rules import RULES, WEIGHT

OVERSIZE = 200_000       # 넘으면 details에 oversize=true (R2 §3, 2단계와 같은 기준)
SCAN_CAP = 300_000       # 검사하는 최대 글자 수
MAX_LINES_PER_RULE = 3

FENCE_OPEN = re.compile(r"^[ \t]{0,3}(`{3,}|~{3,})")


def _line_kinds(lines):
    """줄마다 frontmatter / prose / code."""
    kinds = ["prose"] * len(lines)
    start = 0
    if lines and lines[0].strip() == "---":
        for j in range(1, len(lines)):
            if lines[j].strip() == "---":
                kinds[: j + 1] = ["frontmatter"] * (j + 1)
                start = j + 1
                break
    fence = None
    for k in range(start, len(lines)):
        if fence is None:
            m = FENCE_OPEN.match(lines[k])
            if m:
                fence = m.group(1)
                kinds[k] = "code"
        else:
            kinds[k] = "code"
            t = lines[k].strip()
            if t and set(t) == {fence[0]} and len(t) >= len(fence):  # 같은 문자, 같거나 긴 펜스로만 닫힘
                fence = None
    return kinds


def segment(text):
    """영역별로 같은 길이의 문자열. 대상이 아닌 줄은 공백으로 덮어 원문 위치(줄 번호)를 유지한다."""
    lines = text.split("\n")
    kinds = _line_kinds(lines)
    views = {"all": text}
    for kind in ("frontmatter", "prose", "code"):
        views[kind] = "\n".join(s if k == kind else " " * len(s) for s, k in zip(lines, kinds))
    return views


def _active(rule, base):
    """결합 조건 확인. base = 걸린 규칙 중 결합 전용이 아닌 것의 id."""
    if not rule.requires:
        return True
    if rule.requires == ("*",):
        return bool(base)
    return bool(base & set(rule.requires))


def scan_text(text, rules=RULES):
    """(score, evidence, details)."""
    details = {"oversize": len(text) > OVERSIZE, "scanned_chars": min(len(text), SCAN_CAP), "empty": not text.strip()}
    text = text[:SCAN_CAP]
    views = segment(text)
    newlines = [m.start() for m in re.finditer("\n", text)]
    hits = {}
    for r in rules:
        lines = []
        for m in r.pattern.finditer(views[r.scope]):
            ln = bisect.bisect_right(newlines, m.start()) + 1
            if ln not in lines:
                lines.append(ln)
                if len(lines) == MAX_LINES_PER_RULE:
                    break
        if lines:
            hits[r.id] = lines
    by_id = {r.id: r for r in rules}
    base = {i for i in hits if not by_id[i].requires}
    fired = [r for r in rules if r.id in hits and _active(r, base)]
    keep = 1.0
    for r in fired:
        keep *= 1 - WEIGHT[r.severity]
    fired.sort(key=lambda r: (-WEIGHT[r.severity], hits[r.id][0]))
    evidence = [f"{r.id}@L{ln}" for r in fired for ln in hits[r.id]]
    return 1 - keep, evidence, details
