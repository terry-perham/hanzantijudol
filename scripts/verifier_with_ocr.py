#!/usr/bin/env python3
"""Compatibility wrapper for single-domain verification via unified verifier pipeline.

This script preserves the legacy CLI entry point while delegating all scoring
and OCR decisions to scripts/verifier.py DomainVerifier.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any, Dict, Optional

from verifier import DATA_DIR, DomainVerifier


def to_legacy_payload(result: Dict[str, Any], source_payload: Dict[str, Any]) -> Dict[str, Any]:
    domain = str(result.get("domain", ""))
    status = str(result.get("status", "UNKNOWN"))
    risk_score = float(result.get("risk_score", 0.0))

    analysis = result.get("analysis", {}) if isinstance(result, dict) else {}
    crawl = result.get("crawl", {}) if isinstance(result, dict) else {}
    ocr = analysis.get("ocr_second_pass", {}) if isinstance(analysis, dict) else {}
    ocr_scores = ocr.get("scores", {}) if isinstance(ocr, dict) else {}

    dom_score = ocr_scores.get("ocr_dom_score")
    if dom_score is None:
        dom_score = round(float(analysis.get("heuristic_score", 0.0)) * 10.0, 4)

    ocr_score = ocr_scores.get("ocr_text_score")
    if ocr_score is None:
        ocr_score = 0.0

    ocr_confidence = ocr_scores.get("ocr_confidence")
    if ocr_confidence is None:
        ocr_confidence = 0.0

    payload: Dict[str, Any] = {
        "domain": domain,
        "url": str(crawl.get("final_url") or f"https://{domain}"),
        "timestamp": str(source_payload.get("timestamp", "")),
        "verdict": status,
        "scores": {
            "dom_score": round(float(dom_score), 4),
            "ocr_score": round(float(ocr_score), 4),
            "combined_score": round(risk_score * 10.0, 4),
            "ocr_confidence": round(float(ocr_confidence), 4),
        },
        "ocr_available": bool(ocr.get("ocr_available", False)),
        "screenshot_path": str(ocr.get("screenshot_path") or ""),
        "text_metrics": {
            "dom_length": int(crawl.get("text_length", 0) or 0),
            "ocr_length": 0,
        },
        "thresholds": source_payload.get("config", {}).get("thresholds", {}),
    }

    history_path = ocr.get("history_path")
    if history_path:
        payload["history_path"] = str(history_path)

    return payload


async def verify_domain_with_ocr(
    domain: str,
    screenshot_dir: str,
    output_file: str,
    history_dir: str,
    threshold_profile: Optional[str],
    timeout: int = 30_000,
) -> Dict[str, Any]:
    _ = timeout  # unified verifier uses its own timeout handling internally

    unified_output = Path(output_file).with_name("_tmp_unified_single_report.json")

    verifier = DomainVerifier(
        input_file=DATA_DIR / "candidates_merged.json",
        output_file=unified_output,
        workers=2,
        test_mode=False,
        limit=None,
        single_domain=domain,
        calibration_samples=DATA_DIR / "calibration_samples.json",
        calibration_profile=DATA_DIR / "threshold_profile.json",
        auto_calibration=False,
        enable_ocr_second_pass=True,
        ocr_trigger_statuses="GAMBLING,SUSPICIOUS,BORDERLINE,SAFE,UNKNOWN",
        ocr_confidence_threshold=100.0,
        ocr_screenshot_dir=Path(screenshot_dir),
        ocr_threshold_profile=Path(threshold_profile) if threshold_profile else (DATA_DIR / "threshold_profile_ocr.json"),
        ocr_history_dir=Path(history_dir),
    )

    source_payload = await verifier.verify()
    domains = source_payload.get("domains", []) if isinstance(source_payload, dict) else []
    if not domains:
        raise RuntimeError("unified verifier returned empty domain list")

    legacy = to_legacy_payload(domains[0], source_payload)

    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(legacy, fh, indent=2)

    try:
        if unified_output.exists():
            unified_output.unlink()
    except Exception:
        pass

    return legacy


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify domain via unified verifier OCR second-pass")
    parser.add_argument("--domain", required=True, help="Target domain or URL")
    parser.add_argument("--screenshot-dir", default=str(DATA_DIR / "screenshots"), help="Directory to save screenshots")
    parser.add_argument("--output", default=str(DATA_DIR / "verified_domains_ocr.json"), help="Output JSON file")
    parser.add_argument(
        "--history-dir",
        default=str(DATA_DIR / "ocr-history"),
        help="Directory to store append-only OCR history JSON files",
    )
    parser.add_argument(
        "--threshold-profile",
        default=str(DATA_DIR / "threshold_profile_ocr.json"),
        help="OCR threshold profile JSON",
    )
    parser.add_argument("--timeout", type=int, default=30_000, help="Compatibility timeout argument")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    asyncio.run(
        verify_domain_with_ocr(
            domain=args.domain,
            screenshot_dir=args.screenshot_dir,
            output_file=args.output,
            history_dir=args.history_dir,
            threshold_profile=args.threshold_profile,
            timeout=args.timeout,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
