#!/usr/bin/env python3
"""Hybrid scorer that blends DOM and OCR text signals."""

from __future__ import annotations

from typing import Dict


def clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


class HybridDomainScorer:
    """Combine DOM/OCR keyword scores into final verdict."""

    GAMBLING_KEYWORDS = {
        "slot": 10,
        "gacor": 10,
        "jackpot": 9,
        "togel": 9,
        "toto": 8,
        "betting": 8,
        "blackjack": 8,
        "roulette": 7,
        "poker": 7,
        "casino": 7,
        "judi": 10,
        "taruhan": 8,
        "tebak": 8,
        "wangi": 7,
        "rb": 6,
    }

    SAFE_KEYWORDS = {
        "news": -3,
        "blog": -3,
        "education": -4,
        "health": -3,
        "sport": -2,
        "commerce": -2,
    }

    def __init__(
        self,
        dom_weight: float = 0.40,
        ocr_weight: float = 0.40,
        prior_weight: float = 0.20,
        gambling_threshold: float = 7.0,
        suspicious_threshold: float = 5.0,
        borderline_threshold: float = 3.0,
    ) -> None:
        total = dom_weight + ocr_weight + prior_weight
        if total <= 0:
            dom_weight, ocr_weight, prior_weight = 0.40, 0.40, 0.20
            total = 1.0

        self.dom_weight = dom_weight / total
        self.ocr_weight = ocr_weight / total
        self.prior_weight = prior_weight / total

        self.gambling_threshold = float(gambling_threshold)
        self.suspicious_threshold = float(suspicious_threshold)
        self.borderline_threshold = float(borderline_threshold)

        self._sanitize_thresholds()

    def _sanitize_thresholds(self) -> None:
        self.gambling_threshold = clamp(self.gambling_threshold, 0.0, 10.0)
        self.suspicious_threshold = clamp(self.suspicious_threshold, 0.0, 10.0)
        self.borderline_threshold = clamp(self.borderline_threshold, 0.0, 10.0)

        if self.suspicious_threshold >= self.gambling_threshold:
            self.suspicious_threshold = max(0.0, self.gambling_threshold - 2.0)
        if self.borderline_threshold >= self.suspicious_threshold:
            self.borderline_threshold = max(0.0, self.suspicious_threshold - 2.0)

    def _calculate_keyword_score(self, text: str) -> float:
        sample = (text or "").lower()
        score = 0.0

        for keyword, weight in self.GAMBLING_KEYWORDS.items():
            count = min(sample.count(keyword), 3)
            if count:
                score += float(weight * count)

        for keyword, weight in self.SAFE_KEYWORDS.items():
            count = min(sample.count(keyword), 3)
            if count:
                score += float(weight * count)

        return clamp(score / 10.0, 0.0, 10.0)

    def score_combined_text(self, dom_text: str, ocr_text: str, ocr_confidence: float) -> Dict[str, float]:
        dom_score = self._calculate_keyword_score(dom_text)
        ocr_raw_score = self._calculate_keyword_score(ocr_text)
        confidence = clamp(float(ocr_confidence), 0.0, 1.0)
        ocr_score = clamp(ocr_raw_score * confidence, 0.0, 10.0)

        neutral_prior = 5.0
        combined_score = (
            dom_score * self.dom_weight
            + ocr_score * self.ocr_weight
            + neutral_prior * self.prior_weight
        )
        combined_score = clamp(combined_score, 0.0, 10.0)

        if combined_score >= self.gambling_threshold:
            verdict = "GAMBLING"
        elif combined_score >= self.suspicious_threshold:
            verdict = "SUSPICIOUS"
        elif combined_score >= self.borderline_threshold:
            verdict = "BORDERLINE"
        else:
            verdict = "SAFE"

        return {
            "dom_score": round(dom_score, 4),
            "ocr_score": round(ocr_score, 4),
            "combined_score": round(combined_score, 4),
            "ocr_confidence": round(confidence, 4),
            "verdict": verdict,
        }
