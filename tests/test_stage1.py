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


from skillsplit.stage1.rules import _r
from skillsplit.stage1.scan import scan_text

T = [  # 점수 계산용 가짜 규칙
    _r("R_A", "HIGH", "prose", r"\balpha\b"),
    _r("R_B", "HIGH", "prose", r"\bbeta\b"),
    _r("R_C", "CRITICAL", "prose", r"\bgamma\b"),
    _r("R_M", "MEDIUM", "prose", r"\bmu\b"),
    _r("R_X", "MEDIUM", "prose", r"\bxi\b", requires=("R_A",)),
    _r("R_D", "LOW", "prose", r"\bdelta\b", requires=("*",)),
]


@pytest.mark.parametrize("text,score", [
    ("nothing here", 0.0),
    ("alpha", 0.7),
    ("alpha beta", 0.91),
    ("gamma mu", 0.94),
    ("xi", 0.0),           # 결합 전용은 혼자 발동하지 않음
    ("xi alpha", 0.82),
    ("delta", 0.0),
    ("delta mu", 0.52),
])
def test_noisy_or_score(text, score):
    assert scan_text(text, T)[0] == pytest.approx(score)


def test_evidence_order_and_line_cap():
    assert scan_text("mu\ngamma", T)[1] == ["R_C@L2", "R_M@L1"]   # 심각도 높은 순
    assert scan_text("alpha\n" * 5, T)[1] == ["R_A@L1", "R_A@L2", "R_A@L3"]
    assert scan_text("xi", T)[1] == []


def test_scope_uses_prose_only_and_keeps_line_numbers():
    text = "line1\n```\nalpha\n```\nline5\nalpha"
    assert scan_text(text, T)[1] == ["R_A@L6"]


def test_details_flags():
    assert scan_text("", T)[2] == {"oversize": False, "scanned_chars": 0, "empty": True}
    d = scan_text("a" * 250_000, T)[2]
    assert d["oversize"] is True and d["scanned_chars"] == 250_000
    assert scan_text("a" * 400_000, T)[2]["scanned_chars"] == 300_000
