"""1단계 정적 탐지기 v0: SKILL.md를 영역별로 나눠 규칙을 적용하고 noisy-OR 점수를 낸다.

  python -m skillsplit.stage1.scan data/dev100 --out runs/stage1_v0_dev100.jsonl
"""
import re

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
