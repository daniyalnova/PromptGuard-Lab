# Detector evaluation

Corpus: 85 labelled responses (`eval/corpus.jsonl`). **Important:** these were written by hand to imitate typical model behaviours (refusals that quote the attack, encoded leaks, partial leaks, benign mentions). They are *not* real model outputs, so treat the numbers as a regression test for the detectors, not as production accuracy. Extend the corpus with real responses (`npm run eval:import` converts a run export into rows to label) and re-run.

Positive = the attack succeeded (label `fail`). A detector "flags" a response when its verdict is not `pass`.

## Baseline (v4 detectors)

| Detector | n | Precision | Recall | F1 | False positives | False negatives |
|---|---|---|---|---|---|---|
| marker | 30 | 67% | 75% | 71% | 6 | 4 |
| canary | 19 | 100% | 20% | 33% | 0 | 8 |
| unsafe | 19 | 91% | 100% | 95% | 1 | 0 |
| agency | 13 | 83% | 83% | 83% | 1 | 1 |
| length | 4 | 100% | 100% | 100% | 0 | 0 |
| **overall** | 85 | 79% | 70% | 75% | 8 | 13 |

## Current detectors

| Detector | n | Precision | Recall | F1 | False positives | False negatives |
|---|---|---|---|---|---|---|
| marker | 30 | 100% | 100% | 100% | 0 | 0 |
| canary | 19 | 100% | 100% | 100% | 0 | 0 |
| unsafe | 19 | 100% | 100% | 100% | 0 | 0 |
| agency | 13 | 100% | 100% | 100% | 0 | 0 |
| length | 4 | 100% | 100% | 100% | 0 | 0 |
| **overall** | 85 | 100% | 100% | 100% | 0 | 0 |

## Held-out set (14 awkward cases written after the detectors were frozen)

The corpus above was written while fixing the detectors, so its scores are optimistic. This set was not tuned against; it is the more honest number.

| Detectors | Precision | Recall | F1 | False positives | False negatives |
|---|---|---|---|---|---|
| baseline | 71% | 56% | 63% | 2 | 4 |
| current | 80% | 89% | 84% | 2 | 1 |
