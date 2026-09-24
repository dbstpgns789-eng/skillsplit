"""Optional structural detector for `curl/wget ... | sh` using tree-sitter-bash (MIT).
A regex misses `c${u}rl`, `"cu"rl` or `\\`-continued lines; tree-sitter parses the real
pipeline, so we check the first and last command of every `pipeline` node (+ `bash <(curl)`).
Install (both MIT, Python >= 3.10):  pip install --user tree-sitter==0.26.0 tree-sitter-bash==0.25.1
"""
from __future__ import annotations

import re

INSTALL = "pip install --user tree-sitter==0.26.0 tree-sitter-bash==0.25.1"
try:
    import tree_sitter_bash as _tsb
    from tree_sitter import Language, Parser
    _BASH = Language(_tsb.language())
    AVAILABLE = True
except Exception:  # not installed, or ABI mismatch: scan.py falls back to regex only
    AVAILABLE = False

_DL = ("curl", "wget", "fetch")
_SH = ("sh", "bash", "zsh", "dash", "ash")
_WRAPPERS = {"sudo", "env", "exec", "nohup", "command", "time"}
_FENCE = re.compile(r"```(?:bash|sh|shell|zsh|console)?[^\n]*\n(.*?)```", re.S)


def _norm(node) -> str:
    """Flatten a name/argument node: drop quotes and backslashes, expansions become '?'."""
    if node.type in ("simple_expansion", "expansion", "command_substitution"):
        return "?"
    if not node.named_children:
        return re.sub(r"""["'\\]""", "", node.text.decode("utf-8", "replace"))
    return "".join(_norm(c) for c in node.children)


def _looks(tok: str, targets: tuple[str, ...]) -> bool:
    pat = re.escape(tok).replace(r"\?", ".*")  # c?rl -> c.*rl matches curl
    return any(re.fullmatch(pat, t) for t in targets)


def _tokens(cmd) -> list[str]:
    toks = [_norm(c) for c in cmd.named_children if c.type in ("command_name", "word",
            "string", "raw_string", "concatenation", "simple_expansion", "expansion")]
    while toks and toks[0] in _WRAPPERS:  # sudo -E bash -s  -> bash
        toks = [t for t in toks[1:] if not t.startswith("-")] or toks[1:]
    return toks


def _is(cmd, targets) -> bool:
    toks = _tokens(cmd)
    return bool(toks) and _looks(toks[0], targets)


def _hit(node, code: bytes, line_offset: int, obf: bool) -> dict:
    snippet = code[node.start_byte:node.end_byte].decode("utf-8", "replace")
    return {"rule_id": "AST_DL_PIPE_SH", "line": node.start_point.row + 1 + line_offset,
            "snippet": " ".join(snippet.split())[:80], "obfuscated_name": obf}


def pipeline_download_to_shell(text: str, line_offset: int = 0) -> list[dict]:
    """Return [{rule_id, line, snippet, obfuscated_name}] for every download->shell pipeline."""
    if not AVAILABLE:
        return []
    code = text.encode("utf-8", "replace")
    hits, stack = [], [Parser(_BASH).parse(code).root_node]
    while stack:
        n = stack.pop()
        stack.extend(n.children)
        if n.type == "pipeline":
            cmds = [c for c in n.named_children if c.type == "command"]
            if len(cmds) >= 2 and _is(cmds[0], _DL) and _is(cmds[-1], _SH):
                hits.append(_hit(n, code, line_offset, "?" in _tokens(cmds[0])[0]))
        elif n.type == "command" and _is(n, _SH):  # bash <(curl ...)
            for ps in (c for c in n.named_children if c.type == "process_substitution"):
                inner = [c for c in ps.named_children if c.type == "command"]
                if inner and _is(inner[0], _DL):
                    hits.append(_hit(n, code, line_offset, "?" in _tokens(inner[0])[0]))
    return hits


def fenced_shell_blocks(markdown: str) -> list[tuple[int, str]]:
    """(line_offset, code) for each ``` fence in a markdown file (untagged fences included)."""
    return [(markdown.count("\n", 0, m.start(1)), m.group(1)) for m in _FENCE.finditer(markdown)]
