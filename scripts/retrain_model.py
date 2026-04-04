#!/usr/bin/env python3
"""Weekly adaptive calibration pipeline for sentence-transformer verifier.

This script does not fine-tune transformer weights yet.
It automatically refreshes classification thresholds and source multipliers
from labeled feedback so production behavior improves without manual tuning.
"""

from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"

POSITIVE_LABELS = {"GAMBLING", "JUDOL", "POSITIVE", "MALICIOUS", "BLOCK"}


def utc_now() -> str:
    return datetime.utcnow().isoformat() + "Z"


def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return default


def parse_float(value: Any) -> Optional[float]:
    try:
        return float(value)
    except Exception:
        return None


def normalize_risk_score(value: Any) -> Optional[float]:
    score = parse_float(value)
    if score is None:
        return None

    # Accept 0-1, 0-10, or percentage-like 0-100 scales.
    if score > 1.0:
        if score <= 10.0:
            score = score / 10.0
        elif score <= 100.0:
            score = score / 100.0
        else:
            score = 1.0

    return clamp(score)


def load_feedback_rows(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []

    rows: List[Dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                if isinstance(row, dict):
                    rows.append(row)
    except Exception:
        return []
    return rows


def score_from_row(row: Dict[str, Any]) -> Optional[float]:
    for key in ("risk_score", "score", "combined_score"):
        if key in row:
            parsed = normalize_risk_score(row.get(key))
            if parsed is not None:
                return parsed
    return None


def label_from_row(row: Dict[str, Any]) -> str:
    return str(row.get("label") or row.get("status") or row.get("verdict") or "").strip().upper()


def source_from_row(row: Dict[str, Any]) -> str:
    return str(row.get("source_method") or row.get("source") or row.get("method") or "unknown").strip().lower() or "unknown"


def compute_f1(parsed: Sequence[Tuple[float, int]], threshold: float) -> Tuple[float, float, float]:
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


def calibrate_thresholds(rows: Sequence[Dict[str, Any]], defaults: Dict[str, float]) -> Tuple[Dict[str, float], Dict[str, Any]]:
    parsed: List[Tuple[float, int]] = []
    for row in rows:
        score = score_from_row(row)
        if score is None:
            continue
        label = label_from_row(row)
        if not label:
            continue
        parsed.append((score, 1 if label in POSITIVE_LABELS else 0))

    positives = sum(1 for _, y in parsed if y == 1)
    negatives = sum(1 for _, y in parsed if y == 0)

    if len(parsed) < 20 or positives == 0 or negatives == 0:
        return defaults, {
            "mode": "insufficient_data",
            "sample_count": len(parsed),
            "positives": positives,
            "negatives": negatives,
            "f1": None,
            "precision": None,
            "recall": None,
        }

    best_threshold = defaults.get("gambling", 0.75)
    best_f1 = -1.0
    best_precision = 0.0
    best_recall = 0.0

    for i in range(50, 96):
        threshold = i / 100.0
        f1, precision, recall = compute_f1(parsed, threshold)
        if f1 > best_f1:
            best_f1 = f1
            best_threshold = threshold
            best_precision = precision
            best_recall = recall

    suspicious = max(0.35, best_threshold - 0.20)
    borderline = max(0.20, best_threshold - 0.40)
    if borderline >= suspicious:
        borderline = max(0.20, suspicious - 0.10)

    return {
        "gambling": round(best_threshold, 4),
        "suspicious": round(suspicious, 4),
        "borderline": round(borderline, 4),
    }, {
        "mode": "auto_calibrated",
        "sample_count": len(parsed),
        "positives": positives,
        "negatives": negatives,
        "f1": round(best_f1, 4),
        "precision": round(best_precision, 4),
        "recall": round(best_recall, 4),
    }


def build_source_profile(rows: Sequence[Dict[str, Any]], min_source_samples: int) -> Dict[str, Any]:
    grouped: Dict[str, List[int]] = {}
    for row in rows:
        label = label_from_row(row)
        if not label:
            continue
        source = source_from_row(row)
        grouped.setdefault(source, []).append(1 if label in POSITIVE_LABELS else 0)

    sources: Dict[str, Any] = {}
    for source, labels in sorted(grouped.items()):
        verified_count = len(labels)
        positives = sum(labels)
        precision = positives / verified_count if verified_count else 0.0

        if verified_count < min_source_samples:
            recommended = 1.0
            mode = "insufficient_data"
        else:
            recommended = max(0.85, min(1.15, 1.0 + ((precision - 0.50) * 0.40)))
            mode = "adaptive"

        sources[source] = {
            "score_multiplier": round(recommended, 4),
            "recommended_multiplier": round(recommended, 4),
            "precision": round(precision, 4),
            "verified_count": verified_count,
            "locked": False,
            "calibration_mode": mode,
            "updated_at": utc_now(),
        }

    return {
        "updated_at": utc_now(),
        "version": "1.0",
        "min_verified_samples": max(1, int(min_source_samples)),
        "sources": sources,
    }


def build_threshold_profile(existing_profile: Dict[str, Any], thresholds: Dict[str, float], calibration_report: Dict[str, Any]) -> Dict[str, Any]:
    weights = existing_profile.get("weights", {}) if isinstance(existing_profile, dict) else {}
    quality = existing_profile.get("quality", {}) if isinstance(existing_profile, dict) else {}

    if not isinstance(weights, dict):
        weights = {}
    if not isinstance(quality, dict):
        quality = {}

    if "ai" not in weights:
        weights["ai"] = 0.65
    if "heuristic" not in weights:
        weights["heuristic"] = 0.35
    if "min_text_length" not in quality:
        quality["min_text_length"] = 150

    return {
        "updated_at": utc_now(),
        "thresholds": thresholds,
        "weights": weights,
        "quality": quality,
        "calibration": calibration_report,
    }


def build_metadata(
    feedback_rows: Sequence[Dict[str, Any]],
    calibration_report: Dict[str, Any],
    threshold_profile_path: Path,
    source_profile_path: Path,
) -> Dict[str, Any]:
    return {
        "timestamp": utc_now(),
        "model_type": "sentence-transformers",
        "base_model": "all-MiniLM-L6-v2",
        "training_mode": "calibration-only",
        "feedback_samples": len(feedback_rows),
        "status": "calibrated",
        "note": "Transformer fine-tuning is optional; this run updates operational thresholds and source multipliers automatically.",
        "calibration": calibration_report,
        "artifacts": {
            "threshold_profile": str(threshold_profile_path),
            "source_calibration_profile": str(source_profile_path),
        },
        "quality_gate": {
            "target_precision": 0.87,
            "target_recall": 0.87,
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run weekly adaptive calibration artifacts for verifier")
    parser.add_argument(
        "--feedback",
        default=str(DATA_DIR / "feedback.csv"),
        help="Feedback CSV with labels",
    )
    parser.add_argument(
        "--output",
        default=str(MODELS_DIR / "model-metadata.json"),
        help="Output metadata JSON",
    )
    parser.add_argument(
        "--threshold-profile-output",
        default=str(DATA_DIR / "threshold_profile.json"),
        help="Output threshold profile JSON used by verifier",
    )
    parser.add_argument(
        "--source-calibration-output",
        default=str(DATA_DIR / "source_calibration_profile.json"),
        help="Output source calibration profile JSON used by verifier",
    )
    parser.add_argument(
        "--min-source-samples",
        type=int,
        default=10,
        help="Minimum labeled samples per source before adaptive multipliers are applied",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    feedback_path = Path(args.feedback)
    metadata_path = Path(args.output)
    threshold_profile_path = Path(args.threshold_profile_output)
    source_profile_path = Path(args.source_calibration_output)

    rows = load_feedback_rows(feedback_path)

    existing_threshold_profile = load_json(threshold_profile_path, {})
    existing_thresholds = existing_threshold_profile.get("thresholds", {}) if isinstance(existing_threshold_profile, dict) else {}
    defaults = {
        "gambling": clamp(float(existing_thresholds.get("gambling", 0.75))) if isinstance(existing_thresholds, dict) else 0.75,
        "suspicious": clamp(float(existing_thresholds.get("suspicious", 0.55))) if isinstance(existing_thresholds, dict) else 0.55,
        "borderline": clamp(float(existing_thresholds.get("borderline", 0.35))) if isinstance(existing_thresholds, dict) else 0.35,
    }

    thresholds, calibration_report = calibrate_thresholds(rows, defaults)
    threshold_profile = build_threshold_profile(existing_threshold_profile, thresholds, calibration_report)
    source_profile = build_source_profile(rows, min_source_samples=max(1, int(args.min_source_samples)))
    metadata = build_metadata(
        feedback_rows=rows,
        calibration_report=calibration_report,
        threshold_profile_path=threshold_profile_path,
        source_profile_path=source_profile_path,
    )

    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    threshold_profile_path.parent.mkdir(parents=True, exist_ok=True)
    threshold_profile_path.write_text(json.dumps(threshold_profile, indent=2), encoding="utf-8")

    source_profile_path.parent.mkdir(parents=True, exist_ok=True)
    source_profile_path.write_text(json.dumps(source_profile, indent=2), encoding="utf-8")

    print(
        json.dumps(
            {
                "metadata": str(metadata_path),
                "threshold_profile": str(threshold_profile_path),
                "source_profile": str(source_profile_path),
                "feedback_samples": len(rows),
                "calibration": calibration_report,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
