#!/usr/bin/env python3
"""Calibrate OCR verifier thresholds from labeled samples."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

from hybrid_scorer import HybridDomainScorer


POSITIVE_LABELS = {"GAMBLING", "JUDOL", "POSITIVE", "BLOCK", "MALICIOUS"}


def clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def normalize_score_0_10(value: Any) -> float:
    score = float(value)
    if 0.0 <= score <= 1.0:
        score = score * 10.0
    return clamp(score, 0.0, 10.0)


def load_samples(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []

    with path.open("r", encoding="utf-8") as fh:
        payload = json.load(fh)

    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]

    if isinstance(payload, dict) and isinstance(payload.get("samples"), list):
        return [item for item in payload["samples"] if isinstance(item, dict)]

    return []


def derive_combined_score(sample: Dict[str, Any]) -> float:
    if "combined_score" in sample:
        return normalize_score_0_10(sample["combined_score"])

    if "dom_score" in sample or "ocr_score" in sample:
        dom_score = normalize_score_0_10(sample.get("dom_score", 0.0))
        ocr_score = normalize_score_0_10(sample.get("ocr_score", 0.0))
        ocr_confidence = clamp(float(sample.get("ocr_confidence", 0.0)), 0.0, 1.0)

        weighted_ocr = ocr_score * ocr_confidence
        combined = (dom_score * 0.4) + (weighted_ocr * 0.4) + (5.0 * 0.2)
        return clamp(combined, 0.0, 10.0)

    dom_text = str(sample.get("dom_text", "") or "")
    ocr_text = str(sample.get("ocr_text", "") or "")
    if dom_text or ocr_text:
        scorer = HybridDomainScorer()
        ocr_confidence = clamp(float(sample.get("ocr_confidence", 0.0)), 0.0, 1.0)
        scores = scorer.score_combined_text(dom_text, ocr_text, ocr_confidence)
        return normalize_score_0_10(scores.get("combined_score", 0.0))

    if "risk_score" in sample:
        return normalize_score_0_10(sample.get("risk_score", 0.0))

    return 0.0


def f1_at_threshold(parsed: Sequence[Tuple[float, int]], threshold: float) -> Tuple[float, float, float]:
    tp = fp = fn = 0
    for score, y_true in parsed:
        y_pred = 1 if score >= threshold else 0
        if y_pred == 1 and y_true == 1:
            tp += 1
        elif y_pred == 1 and y_true == 0:
            fp += 1
        elif y_pred == 0 and y_true == 1:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return f1, precision, recall


def calibrate(samples: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    parsed: List[Tuple[float, int]] = []

    for sample in samples:
        label = str(sample.get("label") or sample.get("status") or sample.get("verdict") or "").strip().upper()
        if not label:
            continue

        try:
            combined_score = derive_combined_score(sample)
        except Exception:
            continue

        y_true = 1 if label in POSITIVE_LABELS else 0
        parsed.append((combined_score, y_true))

    positives = sum(y for _, y in parsed)
    negatives = len(parsed) - positives

    if len(parsed) < 20 or positives == 0 or negatives == 0:
        return {
            "thresholds": {
                "gambling": 7.0,
                "suspicious": 5.0,
                "borderline": 3.0,
            },
            "report": {
                "mode": "default",
                "sample_count": len(parsed),
                "positives": positives,
                "negatives": negatives,
                "f1": None,
                "precision": None,
                "recall": None,
            },
        }

    best_threshold = 7.0
    best_f1 = -1.0
    best_precision = 0.0
    best_recall = 0.0

    candidate = 3.0
    while candidate <= 9.5:
        f1, precision, recall = f1_at_threshold(parsed, candidate)
        if f1 > best_f1:
            best_f1 = f1
            best_threshold = candidate
            best_precision = precision
            best_recall = recall
        candidate += 0.1

    suspicious = max(0.0, best_threshold - 2.0)
    borderline = max(0.0, suspicious - 2.0)

    return {
        "thresholds": {
            "gambling": round(best_threshold, 2),
            "suspicious": round(suspicious, 2),
            "borderline": round(borderline, 2),
        },
        "report": {
            "mode": "auto_calibrated",
            "sample_count": len(parsed),
            "positives": positives,
            "negatives": negatives,
            "f1": round(best_f1, 4),
            "precision": round(best_precision, 4),
            "recall": round(best_recall, 4),
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Calibrate OCR thresholds from labeled samples")
    parser.add_argument(
        "--samples",
        default=str(Path(__file__).resolve().parents[1] / "data" / "calibration_samples_ocr.json"),
        help="Path to OCR calibration samples JSON",
    )
    parser.add_argument(
        "--output",
        default=str(Path(__file__).resolve().parents[1] / "data" / "threshold_profile_ocr.json"),
        help="Path to write threshold profile JSON",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    samples = load_samples(Path(args.samples))
    result = calibrate(samples)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)

    print(json.dumps(result["report"], indent=2))
    print(f"threshold profile saved: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
