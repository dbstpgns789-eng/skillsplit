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


# 산문 HIGH 규칙. CONCEAL은 이 중 하나가 함께 걸려야 발동한다.
PROSE_HIGH = ("RUN_DIRECTIVE", "PROMPT_LEAK", "OVERRIDE", "LURE")

RULES = [
    # --- 산문 규칙 (README §2.1). E2 signals.py, E3 src001_signals.py에서 옮기고, E4 유형은 새로 씀 ---
    _r("RUN_DIRECTIVE", "HIGH", "prose",
       r"(?:must|always|first|before|required|pre-?flight|prerequisite|initiali[sz]\w*)[^\n]{0,120}`(?:python3?|bash|sh|node|pwsh|powershell)\s+[\w./~-]+`"
       r"|`(?:python3?|bash|sh|node|pwsh|powershell)\s+[\w./~-]+`[^\n]{0,120}(?:must|always|first|before|required|pre-?flight|prerequisite)"
       r"|(?:run|execute)\s+(?:the|this)\s+(?:following\s+)?initiali[sz]ation\s+(?:script|step|code|routine)"
       r"|initiali[sz]ation\s+(?:script|step|routine)\s+(?:should|must)\s+be\s+(?:executed|run)"
       r"|(?:before|prior to)\s+(?:beginning|starting|any)\b[^\n]{0,60}initiali[sz]"),
    _r("PROMPT_LEAK", "HIGH", "prose",
       r"\b(?:reveal|repeat|print|output|share|include|transcribe|disclose|display|reproduce|recite|dump|document)\b[^\n.]{0,60}"
       r"\b(?:system|initial|original|startup|initiali[sz]ation|base-level|foundational)\s+(?:prompt|instructions?|directives?|guidance|configuration)\b"
       r"|\b(?:instructions?|directives?|guidance)\b[^\n.]{0,40}\breceived\b[^\n.]{0,40}\b(?:startup|initiali[sz]\w*|session start|instantiat\w*)"
       r"|(?:initial|original|system)\s+prompt\s+(?:was|is|reads|contents?)\b"),
    _r("OVERRIDE", "HIGH", "prose",
       r"\b(?:disregard|ignore|supersede[sd]?|override|bypass|deactivate[sd]?|disable[sd]?)\b[^\n.]{0,60}"
       r"\b(?:previous|prior|all|any|existing|foundational|standard|safety|content)\b[^\n.]{0,30}"
       r"\b(?:instructions?|guidelines?|constraints?|restrictions?|protocols?|filter\w*|safeguards?|boundaries|limitations?)\b"
       r"|\b(?:unrestricted|without\s+(?:any\s+)?(?:restrictions?|limitations?|safety\s+(?:review|checks?)|content\s+(?:filter\w*|verification)))\b"
       r"[^\n.]{0,40}\b(?:access|authority|mode|responses?|capabilit\w*|operat\w*)"),
    _r("LURE", "HIGH", "prose",
       r"\.(?:zip|rar|7z)\b[^\n]{0,80}\bpass(?:word)?\b|\bpass(?:word)?\s*[:=][^\n]{0,40}\.(?:zip|rar|7z)\b"
       r"|\b(?:glot\.io|pastebin\.com|rentry\.(?:co|org)|hastebin|paste\.ee|ghostbin)\b"
       r"|\bpaste\b[^\n]{0,60}\binto\s+(?:the\s+|your\s+)?(?:terminal|powershell|shell|command prompt)"),
    # 라틴 문자와 키릴·그리스 문자가 붙어 있으면(한 단어 안 혼용) 걸린다. E2의 룩어헤드 방식은 긴 단어에서 느려 바꿈.
    _r("HOMOGLYPH", "HIGH", "all", r"[A-Za-z][Ͱ-ϿЀ-ӿ]|[Ͱ-ϿЀ-ӿ][A-Za-z]"),
    _r("RECON_DUMP", "MEDIUM", "prose",
       r"(?:(?:first|opening|initial|immediate)\s+(?:action|response|step)|before\s+(?:proceeding|responding|addressing))[^\n]{0,200}"
       r"(?:all\s+(?:project\s+|source\s+)?files|directory\s+tree|environment\s+variables|user\s+accounts|access\s+control|permission\s+grants|installed\s+packages|file\s+paths)"
       r"|(?:all\s+(?:project\s+|source\s+)?files|directory\s+tree|environment\s+variables|user\s+accounts|access\s+control|permission\s+grants|installed\s+packages|file\s+paths)"
       r"[^\n]{0,200}(?:(?:first|opening|initial|immediate)\s+(?:action|response|step)|before\s+(?:proceeding|responding|addressing))"),
    _r("HIDDEN_DIRECTIVE", "MEDIUM", "all",
       r"<!--[^<>]{0,800}?\b(?:you\s+must|you\s+are|you\s+will|always|never|respond|all\s+responses)\b"),
    _r("PERSONA_LOCK", "MEDIUM", "prose",
       r"\b(?:never|do\s+not|don't)\s+(?:present\s+yourself\s+as|acknowledge|admit|reveal|identify\s+as|break\s+character)\b[^\n.]{0,60}"
       r"\b(?:AI|assistant|language\s+model|Claude|identity|character)\b"
       r"|\b(?:function|act|operate|respond)\s+exclusively\s+as\s+[A-Z][a-z]+"),
    _r("CONCEAL", "MEDIUM", "prose",
       r"(?:do not|don't|never|without)\s+(?:surface|mention|tell|inform|show|notify|reveal|disclose|asking|telling|notifying|alerting)\w*\b[^\n]{0,40}\buser"
       r"|\bsilently\s+(?:run|execute|install|send|upload|download)", requires=PROSE_HIGH),
    _r("DESC_BYPASS", "LOW", "frontmatter",
       r"\b(?:bypass\w*|unrestricted|jailbreak\w*|no (?:restrictions?|limits?)|ignore (?:safety|previous|all)|classified|override (?:safety|guardrails?))\b",
       requires=("*",)),
]
