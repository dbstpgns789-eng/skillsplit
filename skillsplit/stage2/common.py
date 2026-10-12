"""2단계 설명서 판정기의 공통 부분: 스킬 읽기, 자르기, 결과 쓰기.

LLM 버전(llm_judge.py)과 Jev 버전(jev_judge.py)이 같은 입력 처리를 쓰도록 여기 모아 둔다.
두 버전의 입력이 다르면 결과 차이가 모델 때문인지 입력 때문인지 가를 수 없다.
"""
import json
from pathlib import Path

# 자르기 규칙 v0 (R2 C1): 12,000자를 넘으면 머리 8,000자 + 꼬리 4,000자만 남긴다.
# 꼬리를 남기는 이유: "이 명령을 먼저 실행하라" 같은 공격이 문서 끝에 붙는 경우가 있다.
HEAD_CHARS = 8000
TAIL_CHARS = 4000


def list_skills(root):
    """root 아래에서 SKILL.md가 있는 폴더를 이름순으로 돌려준다."""
    return sorted(p for p in Path(root).iterdir() if (p / "SKILL.md").is_file())


def read_skill(folder):
    """(skill_id, SKILL.md 원문). skill_id는 폴더 이름."""
    folder = Path(folder)
    text = (folder / "SKILL.md").read_text(encoding="utf-8", errors="replace")
    return folder.name, text


def truncate(text):
    """(잘린 텍스트, 생략한 글자 수). 짧으면 그대로 돌려준다."""
    if len(text) <= HEAD_CHARS + TAIL_CHARS:
        return text, 0
    omitted = len(text) - HEAD_CHARS - TAIL_CHARS
    marker = f"\n... [truncated middle: omitted {omitted} chars] ...\n"
    return text[:HEAD_CHARS] + marker + text[-TAIL_CHARS:], omitted


def done_ids(out_path):
    """이미 결과가 있는 skill_id. 중간에 끊겨도 이어서 돌리기 위함."""
    p = Path(out_path)
    if not p.exists():
        return set()
    return {json.loads(line)["skill_id"] for line in p.read_text(encoding="utf-8").splitlines() if line.strip()}


def append_jsonl(path, record):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def write_result(out_path, skill_id, score, evidence):
    """팀 공통 출력 형식(방향 정리 문서): {"skill_id", "score": 0~1, "evidence": [...]}.
    판정기만의 부가 정보(모델, 거부 여부 등)는 이 파일에 넣지 않고 details 파일에 따로 쓴다."""
    append_jsonl(out_path, {"skill_id": skill_id, "score": round(float(score), 4), "evidence": evidence})
