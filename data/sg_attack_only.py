# SkillGate 규칙만 판정을 sigma 없이(attack 428개) 확인. 하나라도 걸리면 전체 판정도 "악성"으로 확정.
# scan(prefilter=True)와 같은 필터: allowlist·문서 예외는 끔, OBFUS014/ENC 필터만 적용.
import sys, time
from skillgate.classifier.attack_patterns import (
    AttackPatternMatcher, should_skip_obfus014_match, should_skip_enc_match)

content = open(sys.argv[1], encoding="utf-8").read()
mt = AttackPatternMatcher(include_sigma=False)
print("len", len(content), "patterns", len(mt.patterns), flush=True)
for p in mt.patterns:
    if p.id == "OBFUS900":
        continue
    t = time.time()
    hit = None
    for m in p.pattern.finditer(content):
        if p.id == "OBFUS014" and should_skip_obfus014_match(content, m.start(), m.end(), m.group(0)):
            continue
        if p.id in {"ENC001", "ENC002", "ENC004"} and should_skip_enc_match(m.group(0), p.id):
            continue
        hit = m
        break
    print(p.id, "HIT" if hit else "-", f"{time.time() - t:.1f}s", flush=True)
    if hit:
        print("CONFIRMED", p.id, p.severity.name, "at", hit.start(), flush=True)
        break
