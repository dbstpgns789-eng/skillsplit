"""Evaluate one or more prediction files against the manifest.

Usage:
    python eval/evaluate.py --manifest data/manifest.csv \
        --pred stage1=runs/stage1_v1.csv --pred stage2=runs/stage2_v1.csv \
        [--split dev|test|all] [--threshold 0.5] [--out results.md]

Inputs follow docs/data-format.md. Every skill in the selected split must have
a score in every prediction file; missing rows are counted as score 0.0 and
reported.
"""
import argparse
import csv
import sys
from collections import defaultdict

import numpy as np
from sklearn.metrics import average_precision_score, roc_curve


def read_csv(path):
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def recall_at_fpr(y, s, max_fpr=0.01):
    """Max TPR among ROC points with FPR <= max_fpr."""
    if y.sum() == 0 or (1 - y).sum() == 0:
        return float("nan")
    fpr, tpr, _ = roc_curve(y, s)
    ok = fpr <= max_fpr
    return float(tpr[ok].max()) if ok.any() else 0.0


def point_metrics(y, s, thr):
    p = s >= thr
    tp = int((p & (y == 1)).sum()); fp = int((p & (y == 0)).sum())
    fn = int((~p & (y == 1)).sum()); tn = int((~p & (y == 0)).sum())
    prec = tp / (tp + fp) if tp + fp else float("nan")
    rec = tp / (tp + fn) if tp + fn else float("nan")
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else float("nan")
    fpr = fp / (fp + tn) if fp + tn else float("nan")
    return dict(precision=prec, recall=rec, f1=f1, fpr=fpr, tp=tp, fp=fp, fn=fn, tn=tn)


def metrics(y, s, thr):
    y = np.asarray(y, dtype=int); s = np.asarray(s, dtype=float)
    out = dict(n=len(y), n_mal=int(y.sum()))
    if y.sum() and (1 - y).sum():
        out["pr_auc"] = float(average_precision_score(y, s))
        out["recall_at_1pct_fpr"] = recall_at_fpr(y, s, 0.01)
    else:
        out["pr_auc"] = float("nan"); out["recall_at_1pct_fpr"] = float("nan")
    out.update(point_metrics(y, s, thr))
    return out


def fmt(v):
    if isinstance(v, float):
        return "nan" if np.isnan(v) else f"{v:.3f}"
    return str(v)


def table(rows, cols):
    lines = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for r in rows:
        lines.append("| " + " | ".join(fmt(r.get(c, "")) for c in cols) + " |")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--pred", action="append", required=True, help="name=path")
    ap.add_argument("--split", default="dev", choices=["dev", "test", "all"])
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--out")
    a = ap.parse_args()

    man = read_csv(a.manifest)
    if a.split != "all":
        man = [r for r in man if r["split"] == a.split]
    quarantined = [r for r in man if r.get("intact", "") == "0"]
    if quarantined:
        print(f"WARNING: {len(quarantined)} skills are not intact on the machine that built the manifest "
              f"(antivirus quarantine?); they are excluded from this evaluation.", file=sys.stderr)
        man = [r for r in man if r.get("intact", "") != "0"]
    ids = [r["skill_id"] for r in man]
    y = np.array([int(r["label"]) for r in man])

    preds, missing = {}, {}
    for spec in a.pred:
        name, path = spec.split("=", 1)
        d = {r["skill_id"]: r for r in read_csv(path)}
        s = np.zeros(len(ids))
        miss = 0
        for i, k in enumerate(ids):
            r = d.get(k)
            if r is None or r.get("score", "") == "":
                miss += 1
            else:
                s[i] = float(r["score"])
        preds[name] = s; missing[name] = miss

    groups = {
        "all": lambda r: "all",
        "origin_group": lambda r: r["origin_group"],
        "vector": lambda r: r["vector"] or "(none)",
        "dataset": lambda r: r["dataset"],
    }
    cols = ["pred", "group", "value", "n", "n_mal", "pr_auc", "recall_at_1pct_fpr",
            "precision", "recall", "f1", "fpr"]
    out = [f"# Evaluation (split={a.split}, threshold={a.threshold})", ""]
    for name, s in preds.items():
        out.append(f"- `{name}`: {missing[name]} skills without a score (counted as 0.0)")
    out.append("")
    rows = []
    for name, s in preds.items():
        for g, fn in groups.items():
            buckets = defaultdict(list)
            for i, r in enumerate(man):
                buckets[fn(r)].append(i)
            for val, idx in sorted(buckets.items()):
                idx = np.array(idx)
                m = metrics(y[idx], s[idx], a.threshold)
                m.update(pred=name, group=g, value=val)
                rows.append(m)
    out.append(table(rows, cols)); out.append("")

    if len(preds) == 2:
        (n1, s1), (n2, s2) = preds.items()
        p1 = s1 >= a.threshold; p2 = s2 >= a.threshold
        out.append(f"## Overlap on malicious skills at threshold {a.threshold} ({n1} vs {n2})\n")
        orows = []
        for g in ["origin_group", "vector"]:
            buckets = defaultdict(list)
            for i, r in enumerate(man):
                if y[i] == 1:
                    buckets[groups[g](r)].append(i)
            for val, idx in sorted(buckets.items()):
                idx = np.array(idx)
                orows.append(dict(group=g, value=val, n_mal=len(idx),
                                  both=int((p1[idx] & p2[idx]).sum()),
                                  only_1=int((p1[idx] & ~p2[idx]).sum()),
                                  only_2=int((~p1[idx] & p2[idx]).sum()),
                                  neither=int((~p1[idx] & ~p2[idx]).sum())))
        out.append(table(orows, ["group", "value", "n_mal", "both", "only_1", "only_2", "neither"]))
        out.append("")
        # benign false positives overlap
        b = y == 0
        out.append(f"Benign flagged: {n1} only={int((p1 & ~p2 & b).sum())}, "
                   f"{n2} only={int((~p1 & p2 & b).sum())}, both={int((p1 & p2 & b).sum())}, "
                   f"of {int(b.sum())} benign")

    text = "\n".join(out)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(text)
    print(text)


if __name__ == "__main__":
    sys.exit(main())
