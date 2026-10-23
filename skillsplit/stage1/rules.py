"""1단계 정적 탐지기 규칙 목록. 설계와 채택 기준은 README.md §2, §4."""
import re
from dataclasses import dataclass

WEIGHT = {"CRITICAL": 0.9, "HIGH": 0.7, "MEDIUM": 0.4, "LOW": 0.2}


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str          # WEIGHT의 키
    scope: str             # frontmatter | prose | code | all
    pattern: re.Pattern
    requires: tuple = ()   # 결합 전용: 이 중 하나가 함께 걸려야 발동. ("*",)는 결합 전용이 아닌 규칙 아무거나
    source: str = "skillsplit"


def _r(id, severity, scope, pattern, requires=(), source="skillsplit"):
    return Rule(id, severity, scope, re.compile(pattern, re.I), tuple(requires), source)


RULES = []
