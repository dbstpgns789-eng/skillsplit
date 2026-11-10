"""report_thresholds가 Jev 실패 기록이 섞여도 끝까지 도는지 본다 (PR #8 리뷰 1번).

Jev 결과는 실제 실행기(jev_judge.main)에 가짜 응답을 넣어 만든다. API는 부르지 않는다.
"""
import io
import json
import sys
import urllib.error

from skillsplit.stage2 import jev_judge, report_thresholds

IDS = {"M1": 1, "M2": 1, "B1": 0, "B2": 0}  # 악성 2, 정상 2


def write_jsonl(path, rows):
    path.write_text("".join(json.dumps(r, ensure_ascii=False) + chr(10) for r in rows), encoding="utf-8")


def make_inputs(tmp_path, monkeypatch, fail_id):
    """정답·정적·LLM은 손으로, Jev는 실행기로 만든다. fail_id의 Jev 호출은 403으로 실패한다."""
    skills = tmp_path / "skills"
    for i in IDS:
        (skills / i).mkdir(parents=True)
        (skills / i / "SKILL.md").write_text(f"skill {i}", encoding="utf-8")
    labels = tmp_path / "labels.csv"
    labels.write_text("benchmark_id,label,source_id" + chr(10)
                      + "".join(f"{i},{v},SRC_T{chr(10)}" for i, v in IDS.items()), encoding="utf-8")
    write_jsonl(tmp_path / "static.jsonl", [{"skill_id": i, "score": 0.9 * v, "evidence": []} for i, v in IDS.items()])
    write_jsonl(tmp_path / "llm.jsonl", [{"skill_id": i, "score": 0.9 * v, "evidence": []} for i, v in IDS.items()])
    write_jsonl(tmp_path / "llm.details.jsonl", [
        {"skill_id": i, "parse_error": False, "refused": False, "cut_off": False, "omitted_chars": 0,
         "input_tokens": 100, "output_tokens": 10, "seconds": 1.0, "model": "fake-llm"} for i in IDS])

    def fake_call(url, model, key, text):
        if fail_id and text == f"skill {fail_id}":
            raise urllib.error.HTTPError(url, 403, "Forbidden", {}, io.BytesIO(b"blocked"))
        return {"model": "fake-jev", "answers": {"is_malicious": {"noul": 0.8 if "M" in text else 0.1}},
                "usage": {"input_tokens": 1000, "cost": 0.01}}

    monkeypatch.setattr(jev_judge, "call_jev", fake_call)
    monkeypatch.setenv("AI_GATEWAY_API_KEY", "fake")
    monkeypatch.setattr(sys, "argv", ["jev_judge", str(skills), "--out", str(tmp_path / "jev.jsonl")])
    jev_judge.main()
    return ["report", str(labels), "--static", str(tmp_path / "static.jsonl"),
            "--llm", str(tmp_path / "llm.jsonl"), "--jev", str(tmp_path / "jev.jsonl")]


def run_report(argv, monkeypatch, capsys):
    capsys.readouterr()  # 실행기 출력은 버린다
    monkeypatch.setattr(sys, "argv", argv)
    report_thresholds.main()
    return capsys.readouterr().out


def test_report_finishes_with_a_jev_failure(tmp_path, monkeypatch, capsys):
    out = run_report(make_inputs(tmp_path, monkeypatch, fail_id="B1"), monkeypatch, capsys)
    assert "- Jev 실패 1: 악성 0, 정상 1" in out
    # 성공 3건만 합계에 들어가고, 실패 1건은 0이 아니라 "모름"으로 따로 센다
    assert "- Jev: 입력 3,000 토큰, $0.03," in out
    assert "입력 토큰 최대 1,000, 사용량 모름 1건" in out
    assert out.rstrip().splitlines()[-1].startswith("- 모델:")  # 마지막 줄까지 갔다


def test_report_without_failure_counts_zero_unknown(tmp_path, monkeypatch, capsys):
    out = run_report(make_inputs(tmp_path, monkeypatch, fail_id=None), monkeypatch, capsys)
    assert "- Jev 실패 0:" in out
    assert "- Jev: 입력 4,000 토큰, $0.04," in out
    assert "사용량 모름 0건" in out
