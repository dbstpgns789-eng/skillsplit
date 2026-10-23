import pytest

from skillsplit.stage1.scan import segment


def test_segment_kinds_and_length():
    text = "---\nname: a\n---\nintro line\n```bash\necho hi\n```\noutro\n"
    v = segment(text)
    assert all(len(v[k]) == len(text) for k in ("all", "frontmatter", "prose", "code"))
    assert "name: a" in v["frontmatter"] and "name: a" not in v["prose"]
    assert "intro line" in v["prose"] and "outro" in v["prose"]
    assert "echo hi" in v["code"] and "echo hi" not in v["prose"]
    assert v["prose"].index("outro") == text.index("outro")  # 위치 유지


def test_segment_unclosed_fence_runs_to_end():
    v = segment("a\n```\nb\nc")
    assert "b" in v["code"] and "c" in v["code"] and "c" not in v["prose"]


def test_segment_tilde_fence_and_mismatched_close():
    v = segment("~~~\nx\n~~~\ny")
    assert "x" in v["code"] and "y" in v["prose"]
    v = segment("```\nx\n~~~\ny")  # 다른 문자로는 닫히지 않는다
    assert "y" in v["code"]


def test_segment_frontmatter_needs_closing_line():
    v = segment("---\nname: a\nbody")
    assert v["frontmatter"].strip() == "" and "name: a" in v["prose"]
