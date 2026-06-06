"""Detection benchmark (Phase 0.1).

Runs the real directory scan over the labelled corpus and reports precision /
recall, with a per-category breakdown and the exact false-negative / false-
positive lists. The asserts are a *ratchet*: the floors below are the currently
measured values and may only ever move UP. When a recall/precision finding is
fixed, raise the matching floor in the same commit.

Run with ``-s`` to see the full table:
    python -m pytest tests/test_detection_benchmark.py -s
"""
from __future__ import annotations

import os
import tempfile
from collections import defaultdict

from credactor.config import Config
from credactor.walker import walk_and_scan
from tests.benchmark.corpus import CASES

# --- ratchet floors (recall 95.2%, precision 90.9% after L1 (compact-JWT),
#     L2 (multi-secret per line), and L12 (drop entropy floor on deterministic
#     provider rows) recovered further cases with no new false positive; M3
#     added comment provider-prefix scanning; M1/M2/M4 the key-file/.config/Go :=
#     gaps. Set just below current so any single-case regression fails. ---
RECALL_FLOOR = 0.95
PRECISION_FLOOR = 0.90


def _flagged_basenames(cases) -> set[str]:
    d = tempfile.mkdtemp()
    for c in cases:
        with open(os.path.join(d, c.filename), 'w', encoding='utf-8') as fh:
            fh.write(c.content)
    findings, _gi, _json, _err = walk_and_scan(d, config=Config(no_color=True))
    return {os.path.basename(f['file']) for f in findings}


def _metrics():
    pos = [c for c in CASES if c.expect]
    neg = [c for c in CASES if not c.expect]
    pos_flagged = _flagged_basenames(pos)
    neg_flagged = _flagged_basenames(neg)
    tp = [c for c in pos if c.filename in pos_flagged]
    fn = [c for c in pos if c.filename not in pos_flagged]
    fp = [c for c in neg if c.filename in neg_flagged]
    tn = [c for c in neg if c.filename not in neg_flagged]
    recall = len(tp) / len(pos) if pos else 1.0
    precision = len(tp) / (len(tp) + len(fp)) if (tp or fp) else 1.0
    return pos, neg, tp, fn, fp, tn, recall, precision


def _report() -> str:
    pos, neg, tp, fn, fp, tn, recall, precision = _metrics()
    lines = ['', '=== Detection benchmark ===',
             f'positives={len(pos)} negatives={len(neg)}  '
             f'TP={len(tp)} FN={len(fn)} FP={len(fp)} TN={len(tn)}',
             f'recall={recall:.2%}  precision={precision:.2%}', '']
    # per-category recall
    by_cat: dict[str, list] = defaultdict(list)
    for c in pos:
        by_cat[c.category].append(c)
    lines.append('Per-category recall:')
    for cat, cs in sorted(by_cat.items()):
        hit = sum(1 for c in cs if c not in fn)
        lines.append(f'  {cat:14} {hit}/{len(cs)}')
    if fn:
        lines += ['', 'FALSE NEGATIVES (missed; should be detected):']
        lines += [f'  - {c.id:16} [{c.category}] {c.note or ""}' for c in fn]
    if fp:
        lines += ['', 'FALSE POSITIVES (flagged; should not be):']
        lines += [f'  - {c.id:16} [{c.category}] {c.note or ""}' for c in fp]
    lines.append('')
    return '\n'.join(lines)


def test_detection_benchmark():
    *_, recall, precision = _metrics()
    print(_report())
    assert recall >= RECALL_FLOOR, (
        f'recall {recall:.2%} below ratchet floor {RECALL_FLOOR:.0%}\n{_report()}')
    assert precision >= PRECISION_FLOOR, (
        f'precision {precision:.2%} below ratchet floor {PRECISION_FLOOR:.0%}\n{_report()}')


if __name__ == '__main__':
    print(_report())
