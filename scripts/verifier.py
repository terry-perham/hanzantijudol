#!/usr/bin/env python3
"""Verification engine: crawl + hybrid scoring + verdict generation.

Best-practice highlights integrated:
- Playwright context-per-domain with explicit close
- Semaphore-based concurrency (default 4)
- Hybrid scoring (AI 60% + heuristic 40%)
- FastText replacement: Sentence-Transformers
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import shutil
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlparse

from dotenv import load_dotenv

try:
    from playwright.async_api import (
        TimeoutError as PlaywrightTimeoutError,
        async_playwright,
    )

    PLAYWRIGHT_AVAILABLE = True
except Exception:
    PLAYWRIGHT_AVAILABLE = False

try:
    import numpy as np
    from sentence_transformers import SentenceTransformer
    from sklearn.metrics.pairwise import cosine_similarity

    AI_AVAILABLE = True
except Exception:
    AI_AVAILABLE = False

try:
    from hybrid_scorer import HybridDomainScorer
    from ocr_processor import OCRProcessor

    OCR_MODULES_AVAILABLE = True
except Exception:
    OCR_MODULES_AVAILABLE = False


load_dotenv()

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("verifier")


def utc_now() -> str:
    return datetime.utcnow().isoformat() + "Z"


def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def normalize_domain_input(raw: str) -> str:
    value = (raw or "").strip()
    if not value:
        return ""

    parsed = urlparse(value if "://" in value else f"https://{value}")
    host = (parsed.netloc or parsed.path).strip().lower()
    if host.startswith("www."):
        host = host[4:]
    return host


def load_ocr_threshold_profile(path: Optional[Path]) -> Dict[str, float]:
    defaults = {
        "gambling": 7.0,
        "suspicious": 5.0,
        "borderline": 3.0,
    }

    if not path:
        return defaults
    if not path.exists():
        return defaults

    try:
        with path.open("r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except Exception as exc:
        logger.warning("failed loading OCR threshold profile %s: %s", path, exc)
        return defaults

    if not isinstance(payload, dict):
        return defaults

    raw = payload.get("thresholds", payload)
    if not isinstance(raw, dict):
        return defaults

    for key in ("gambling", "suspicious", "borderline"):
        value = raw.get(key)
        try:
            if value is not None:
                defaults[key] = float(value)
        except Exception:
            continue

    return defaults


def load_source_calibration_profile(path: Optional[Path]) -> Dict[str, float]:
    """Load score multipliers per source method.

    Expected schema (tolerant):
    {
      "sources": {
        "google_dorking": {"score_multiplier": 1.02},
        "certificate_transparency": {"score_multiplier": 0.93}
      }
    }
    """

    if not path or not path.exists():
        return {}

    try:
        with path.open("r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except Exception as exc:
        logger.warning("failed loading source calibration profile %s: %s", path, exc)
        return {}

    if not isinstance(payload, dict):
        return {}

    try:
        minimum_samples = max(1, int(payload.get("min_verified_samples", 10)))
    except Exception:
        minimum_samples = 10

    raw = payload.get("sources", payload)
    if not isinstance(raw, dict):
        return {}

    out: Dict[str, float] = {}
    for method, node in raw.items():
        multiplier: Optional[float] = None
        if isinstance(node, dict):
            try:
                recommended_multiplier = float(node.get("recommended_multiplier", 1.0))
            except Exception:
                recommended_multiplier = 1.0
            try:
                multiplier = float(node.get("score_multiplier", recommended_multiplier))
            except Exception:
                multiplier = None

            locked = bool(node.get("locked", False))
            try:
                verified_count = int(node.get("verified_count", 0) or 0)
            except Exception:
                verified_count = 0
            calibration_mode = str(node.get("calibration_mode", "")).strip().lower()

            if not locked and (verified_count < minimum_samples or calibration_mode == "insufficient_data"):
                multiplier = 1.0
        else:
            try:
                multiplier = float(node)
            except Exception:
                multiplier = None

        if multiplier is None:
            continue

        out[str(method)] = clamp(multiplier, 0.70, 1.30)

    return out


class ThresholdCalibrator:
    """Calibrate gambling threshold from labeled score samples."""

    POSITIVE_LABELS = {"GAMBLING", "JUDOL", "POSITIVE", "MALICIOUS", "BLOCK"}

    @staticmethod
    def load_samples(path: Path) -> List[Dict[str, Any]]:
        if not path.exists():
            return []

        try:
            with path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception:
            return []

        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
        if isinstance(data, dict) and isinstance(data.get("samples"), list):
            return [x for x in data["samples"] if isinstance(x, dict)]
        return []

    @classmethod
    def calibrate(
        cls,
        samples: Sequence[Dict[str, Any]],
        default_threshold: float,
    ) -> Tuple[Dict[str, float], Dict[str, Any]]:
        parsed: List[Tuple[float, int]] = []

        for row in samples:
            label_raw = str(row.get("label") or row.get("status") or row.get("verdict") or "").strip().upper()
            score_raw = row.get("risk_score", row.get("combined_score", row.get("score")))

            try:
                score = clamp(float(score_raw))
            except Exception:
                continue

            y_true = 1 if label_raw in cls.POSITIVE_LABELS else 0
            parsed.append((score, y_true))

        positives = sum(1 for _, y in parsed if y == 1)
        negatives = sum(1 for _, y in parsed if y == 0)

        if len(parsed) < 20 or positives == 0 or negatives == 0:
            thresholds = {
                "gambling": default_threshold,
                "suspicious": max(0.35, default_threshold - 0.20),
                "borderline": max(0.20, default_threshold - 0.40),
            }
            report = {
                "sample_count": len(parsed),
                "positives": positives,
                "negatives": negatives,
                "f1": None,
                "precision": None,
                "recall": None,
                "mode": "default_threshold",
            }
            return thresholds, report

        best_f1 = -1.0
        best_threshold = default_threshold
        best_precision = 0.0
        best_recall = 0.0

        for i in range(50, 96):
            threshold = i / 100.0
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

            if f1 > best_f1:
                best_f1 = f1
                best_threshold = threshold
                best_precision = precision
                best_recall = recall

        suspicious = max(0.35, best_threshold - 0.20)
        borderline = max(0.20, best_threshold - 0.40)
        if borderline >= suspicious:
            borderline = max(0.20, suspicious - 0.10)

        thresholds = {
            "gambling": best_threshold,
            "suspicious": suspicious,
            "borderline": borderline,
        }
        report = {
            "sample_count": len(parsed),
            "positives": positives,
            "negatives": negatives,
            "f1": round(best_f1, 4),
            "precision": round(best_precision, 4),
            "recall": round(best_recall, 4),
            "mode": "auto_calibrated",
        }
        return thresholds, report


@dataclass
class CrawlResult:
    domain: str
    ok: bool
    final_url: str
    title: str
    text: str
    links: List[str]
    error: Optional[str]


class HeuristicScorer:
    """Keyword-based scoring with weighted tiers."""

    DANGER_WEIGHTS: Dict[str, int] = {
        # Tier 1
        "slot": 10,
        "gacor": 10,
        "maxwin": 10,
        "rtp": 10,
        "scatter": 10,
        "bonus games": 10,
        "slot terpercaya": 10,
        # Tier 2
        "deposit": 8,
        "withdraw": 8,
        "taruhan": 8,
        "jackpot": 8,
        "kemenangan": 7,
        "mahjong": 7,
        "togel": 8,
        # Tier 3
        "rtp live": 6,
        "wd": 5,
        "depo": 5,
        "bonus": 5,
        "free spin": 6,
        "winning": 5,
        "fortune": 5,
        # Tier 4
        "wa.me": 5,
        "telegram": 5,
        "t.me": 5,
        "whatsapp": 4,
        "customer service": 4,
        "hubungi": 4,
        "kontak": 4,
        # Tier 5
        "situs judi": 7,
        "agen slot": 7,
        "bandar": 6,
        "anti blokir": 7,
        "link alternatif": 7,
    }

    SAFE_WEIGHTS: Dict[str, int] = {
        "berita": -3,
        "artikel": -3,
        "blog": -3,
        "news": -2,
        "pemerintah": -4,
        "edukasi": -4,
        "tutorial": -3,
        "wikipedia": -5,
        "github": -5,
        "referensi": -3,
    }

    PAYMENT_PATTERNS: Sequence[str] = (
        "gopay",
        "dana",
        "ovo",
        "bank",
        "transfer",
        "qris",
    )

    CONTACT_PATTERNS: Sequence[str] = (
        "wa.me",
        "telegram",
        "t.me",
        "whatsapp",
    )

    def score(self, text: str, title: str, links: Sequence[str]) -> Dict[str, Any]:
        combined_text = f"{title}\n{text}".lower()
        initial = 0.0

        danger_hits: Dict[str, int] = {}
        safe_hits: Dict[str, int] = {}
        payment_hits = 0
        messaging_hits = 0

        for keyword, weight in self.DANGER_WEIGHTS.items():
            count = combined_text.count(keyword)
            if count:
                danger_hits[keyword] = count
                initial += (weight * count) / 100.0

        for keyword, weight in self.SAFE_WEIGHTS.items():
            count = combined_text.count(keyword)
            if count:
                safe_hits[keyword] = count
                initial += (weight * count) / 100.0

        for link in links[:50]:
            token = link.lower()
            if any(p in token for p in self.PAYMENT_PATTERNS):
                payment_hits += 1
                initial += 0.05
            if any(m in token for m in self.CONTACT_PATTERNS):
                messaging_hits += 1
                initial += 0.03

        score = min(max(initial / 2.0, 0.0), 1.0)

        return {
            "score": round(score, 6),
            "danger_hits": danger_hits,
            "safe_hits": safe_hits,
            "payment_hits": payment_hits,
            "messaging_hits": messaging_hits,
        }


class AIClassifier:
    """Sentence-transformers classifier wrapper.

    If model init fails, verifier gracefully falls back to heuristic-only mode.
    """

    GAMBLING_KEYWORDS: Sequence[str] = (
        "slot gacor",
        "situs judi",
        "togel",
        "betting online",
        "mahjong ways",
        "rtp live",
        "agen slot",
        "link alternatif",
        "maxwin",
        "jackpot",
    )

    def __init__(self, model_name: str = "all-MiniLM-L6-v2") -> None:
        self.model_name = model_name
        self.enabled = False
        self.model: Any = None
        self.gambling_embeddings: Any = None

        if not AI_AVAILABLE:
            logger.warning("ai model unavailable: sentence-transformers dependencies not installed")
            return

        try:
            self.model = SentenceTransformer(model_name)
            self.gambling_embeddings = self.model.encode(
                list(self.GAMBLING_KEYWORDS),
                batch_size=32,
                show_progress_bar=False,
                normalize_embeddings=True,
            )
            self.enabled = True
        except Exception as exc:
            logger.warning("ai model disabled due to init error: %s", exc)
            self.enabled = False

    def score(self, text: str) -> Optional[Dict[str, float]]:
        if not self.enabled or not text.strip():
            return None

        try:
            embedding = self.model.encode(
                [text[:3000]],
                batch_size=1,
                show_progress_bar=False,
                normalize_embeddings=True,
            )
            sims = cosine_similarity(embedding, self.gambling_embeddings)[0]
            max_sim = float(np.max(sims))
            top_k = min(3, len(sims))
            top_mean = float(np.mean(sorted(sims)[-top_k:]))
            calibrated = clamp((0.7 * max_sim) + (0.3 * top_mean))
            return {
                "raw_max": round(max_sim, 6),
                "topk_mean": round(top_mean, 6),
                "calibrated": round(calibrated, 6),
            }
        except Exception as exc:
            logger.warning("ai scoring failed: %s", exc)
            return None


class DomainVerifier:
    """Main verifier pipeline."""

    def __init__(
        self,
        input_file: Path,
        output_file: Path,
        workers: int = 4,
        test_mode: bool = False,
        limit: Optional[int] = None,
        ai_weight: float = 0.60,
        heuristic_weight: float = 0.40,
        gambling_threshold: float = 0.75,
        suspicious_threshold: float = 0.55,
        borderline_threshold: float = 0.35,
        min_text_length: int = 120,
        calibration_samples: Optional[Path] = None,
        calibration_profile: Optional[Path] = None,
        auto_calibration: bool = True,
        single_domain: Optional[str] = None,
        enable_ocr_second_pass: bool = True,
        ocr_trigger_statuses: str = "SUSPICIOUS,BORDERLINE,UNKNOWN",
        ocr_confidence_threshold: float = 70.0,
        ocr_screenshot_dir: Optional[Path] = None,
        ocr_threshold_profile: Optional[Path] = None,
        ocr_history_dir: Optional[Path] = None,
        ocr_history_retention_days: int = 30,
        source_calibration_profile: Optional[Path] = None,
        disable_source_calibration: bool = False,
        require_ai: bool = False,
    ) -> None:
        self.input_file = input_file
        self.output_file = output_file
        self.workers = max(1, workers)
        self.test_mode = test_mode
        self.limit = limit
        self.single_domain = normalize_domain_input(single_domain or "")
        self.min_text_length = max(50, int(min_text_length))
        self.calibration_samples = calibration_samples
        self.calibration_profile = calibration_profile
        self.auto_calibration = auto_calibration
        self.calibration_report: Dict[str, Any] = {
            "mode": "not_run",
            "sample_count": 0,
        }
        self.source_calibration_profile = source_calibration_profile or (DATA_DIR / "source_calibration_profile.json")
        self.source_calibration_enabled = not disable_source_calibration
        self.require_ai = bool(require_ai)
        self.source_multipliers: Dict[str, float] = {}
        self.domain_sources: Dict[str, List[str]] = {}

        parsed_ocr_statuses = {
            part.strip().upper()
            for part in str(ocr_trigger_statuses or "").split(",")
            if part.strip()
        }
        self.ocr_trigger_statuses: Set[str] = parsed_ocr_statuses or {"SUSPICIOUS", "BORDERLINE", "UNKNOWN"}
        self.ocr_confidence_threshold = max(0.0, min(100.0, float(ocr_confidence_threshold)))
        self.ocr_screenshot_dir = ocr_screenshot_dir or (DATA_DIR / "screenshots")
        self.ocr_threshold_profile = ocr_threshold_profile or (DATA_DIR / "threshold_profile_ocr.json")
        self.ocr_history_dir = ocr_history_dir or (DATA_DIR / "ocr-history")
        try:
            self.ocr_history_retention_days = max(1, int(ocr_history_retention_days))
        except Exception:
            self.ocr_history_retention_days = 30
        self.ocr_thresholds = load_ocr_threshold_profile(self.ocr_threshold_profile)

        self.ocr_enabled = bool(enable_ocr_second_pass and OCR_MODULES_AVAILABLE and PLAYWRIGHT_AVAILABLE)
        self.ocr_processor: Optional[Any] = None
        self.ocr_scorer: Optional[Any] = None

        total_weight = ai_weight + heuristic_weight
        if total_weight <= 0:
            ai_weight = 0.60
            heuristic_weight = 0.40
            total_weight = 1.0

        self.ai_weight = ai_weight / total_weight
        self.heuristic_weight = heuristic_weight / total_weight
        self.thresholds: Dict[str, float] = {
            "gambling": clamp(gambling_threshold),
            "suspicious": clamp(suspicious_threshold),
            "borderline": clamp(borderline_threshold),
        }
        self._sanitize_thresholds()

        self.scorer = HeuristicScorer()
        self.ai = AIClassifier(model_name=os.getenv("AI_MODEL_NAME", "all-MiniLM-L6-v2"))
        if self.require_ai and not self.ai.enabled and not self.test_mode:
            raise RuntimeError("ai model unavailable while --require-ai is enabled")

        if self.ocr_enabled:
            self.ocr_processor = OCRProcessor(lang="ind+eng")
            self.ocr_scorer = HybridDomainScorer(
                gambling_threshold=self.ocr_thresholds["gambling"],
                suspicious_threshold=self.ocr_thresholds["suspicious"],
                borderline_threshold=self.ocr_thresholds["borderline"],
            )
            if not self.ocr_processor.available:
                logger.warning("OCR second-pass enabled but tesseract unavailable; runs will stay DOM/AI only")
        else:
            logger.info("OCR second-pass disabled or unavailable in current environment")

    def _sanitize_thresholds(self) -> None:
        gambling = self.thresholds["gambling"]
        suspicious = self.thresholds["suspicious"]
        borderline = self.thresholds["borderline"]

        if suspicious >= gambling:
            suspicious = max(0.30, gambling - 0.20)
        if borderline >= suspicious:
            borderline = max(0.20, suspicious - 0.15)

        self.thresholds = {
            "gambling": round(gambling, 4),
            "suspicious": round(suspicious, 4),
            "borderline": round(borderline, 4),
        }

    def _load_calibration_profile(self) -> None:
        if not self.calibration_profile or not self.calibration_profile.exists():
            return

        try:
            with self.calibration_profile.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception as exc:
            logger.warning("failed reading calibration profile: %s", exc)
            return

        if not isinstance(data, dict):
            return

        thresholds = data.get("thresholds", {})
        if isinstance(thresholds, dict):
            try:
                self.thresholds["gambling"] = clamp(float(thresholds.get("gambling", self.thresholds["gambling"])))
            except Exception:
                pass
            try:
                self.thresholds["suspicious"] = clamp(float(thresholds.get("suspicious", self.thresholds["suspicious"])))
            except Exception:
                pass
            try:
                self.thresholds["borderline"] = clamp(float(thresholds.get("borderline", self.thresholds["borderline"])))
            except Exception:
                pass

        weights = data.get("weights", {})
        if isinstance(weights, dict):
            try:
                ai_weight = float(weights.get("ai", self.ai_weight))
                heuristic_weight = float(weights.get("heuristic", self.heuristic_weight))
            except Exception:
                ai_weight = self.ai_weight
                heuristic_weight = self.heuristic_weight
            total = ai_weight + heuristic_weight
            if total > 0:
                self.ai_weight = ai_weight / total
                self.heuristic_weight = heuristic_weight / total

        quality = data.get("quality", {})
        if isinstance(quality, dict):
            try:
                self.min_text_length = max(50, int(quality.get("min_text_length", self.min_text_length)))
            except Exception:
                pass

        self._sanitize_thresholds()
        self.calibration_report = {
            "mode": "profile_loaded",
            "sample_count": 0,
        }

    def _auto_calibrate_thresholds(self) -> None:
        if not self.auto_calibration:
            return
        if not self.calibration_samples:
            return
        if not self.calibration_samples.exists():
            return

        samples = ThresholdCalibrator.load_samples(self.calibration_samples)
        if not samples:
            return

        thresholds, report = ThresholdCalibrator.calibrate(samples, self.thresholds["gambling"])
        self.thresholds.update(thresholds)
        self._sanitize_thresholds()
        self.calibration_report = report

    def _load_domain_sources_from_input(self) -> None:
        self.domain_sources = {}

        if self.single_domain:
            self.domain_sources[self.single_domain] = ["user_report"]
            return

        if not self.input_file.exists():
            return

        try:
            with self.input_file.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception:
            return

        if not isinstance(data, dict):
            return

        raw = data.get("domain_sources", {})
        if not isinstance(raw, dict):
            return

        for domain, methods in raw.items():
            normalized_domain = normalize_domain_input(str(domain))
            if not normalized_domain:
                continue

            if isinstance(methods, list):
                method_values = [str(m).strip() for m in methods if str(m).strip()]
            elif methods is None:
                method_values = []
            else:
                method_values = [str(methods).strip()] if str(methods).strip() else []

            if not method_values:
                method_values = ["unknown"]

            self.domain_sources[normalized_domain] = sorted(set(method_values))

    def _load_source_calibration_profile(self) -> None:
        self.source_multipliers = {}
        if not self.source_calibration_enabled:
            return
        self.source_multipliers = load_source_calibration_profile(self.source_calibration_profile)

    def _source_multiplier_for_domain(self, domain: str) -> Tuple[float, List[str], Dict[str, float]]:
        methods = self.domain_sources.get(domain) or ["unknown"]
        weights: Dict[str, float] = {}

        for method in methods:
            weights[method] = float(self.source_multipliers.get(method, 1.0))

        if not weights:
            return 1.0, methods, {}

        multiplier = clamp(sum(weights.values()) / len(weights), 0.70, 1.30)
        return multiplier, methods, weights

    def _should_run_ocr_second_pass(self, status: str, confidence: float, crawl: CrawlResult) -> bool:
        if not self.ocr_enabled:
            return False
        if self.ocr_processor is None or self.ocr_scorer is None:
            return False
        if not self.ocr_processor.available:
            return False

        normalized_status = str(status or "UNKNOWN").upper()
        if normalized_status in self.ocr_trigger_statuses:
            return True
        if confidence <= self.ocr_confidence_threshold:
            return True
        if not crawl.ok:
            return True
        if len(crawl.text) < self.min_text_length:
            return True
        return False

    @staticmethod
    def _ocr_candidate_urls(domain: str, crawl: CrawlResult) -> List[str]:
        candidates: List[str] = []
        if crawl.final_url:
            candidates.append(crawl.final_url)
        for url in (f"https://{domain}", f"http://{domain}"):
            if url not in candidates:
                candidates.append(url)
        return candidates

    def _prune_ocr_history(self) -> int:
        if not self.ocr_history_dir.exists():
            return 0

        cutoff = (datetime.utcnow() - timedelta(days=self.ocr_history_retention_days)).date()
        removed = 0

        for partition in self.ocr_history_dir.iterdir():
            if not partition.is_dir():
                continue

            try:
                partition_date = datetime.strptime(partition.name, "%Y-%m-%d").date()
            except Exception:
                continue

            if partition_date < cutoff:
                shutil.rmtree(partition, ignore_errors=True)
                removed += 1

        if removed:
            logger.info(
                "pruned %s OCR history partitions older than %s days",
                removed,
                self.ocr_history_retention_days,
            )

        return removed

    def _write_ocr_history(self, domain: str, record: Dict[str, Any]) -> str:
        partition = utc_now()[:10]
        timestamp = str(record.get("timestamp") or utc_now()).replace(":", "").replace("-", "").replace(".", "")
        history_file = self.ocr_history_dir / partition / f"{domain.replace('.', '_')}_{timestamp}.json"
        history_file.parent.mkdir(parents=True, exist_ok=True)
        with history_file.open("w", encoding="utf-8") as fh:
            json.dump(record, fh, indent=2)
        return history_file.as_posix()

    async def _capture_screenshot_with_browser(
        self,
        browser: Any,
        url: str,
        output_path: str,
        timeout: int = 30_000,
    ) -> bool:
        if not browser:
            return False

        candidate = str(url or "").strip()
        if not candidate:
            return False
        if not candidate.startswith("http://") and not candidate.startswith("https://"):
            candidate = f"https://{candidate}"

        parsed = urlparse(candidate)
        if not parsed.scheme or not parsed.netloc:
            return False

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        context: Any = None
        page: Any = None
        try:
            context = await browser.new_context(
                viewport={"width": 1280, "height": 720},
                ignore_https_errors=True,
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
                ),
            )
            page = await context.new_page()
            try:
                await page.goto(candidate, wait_until="domcontentloaded", timeout=timeout)
            except PlaywrightTimeoutError:
                logger.warning("page timeout while capturing screenshot: %s", candidate)
            except Exception as exc:
                logger.warning("navigation error while capturing screenshot (%s): %s", candidate, exc)

            await asyncio.sleep(1.5)
            await page.screenshot(path=str(path), full_page=True)
            return True
        except Exception as exc:
            logger.warning("failed to capture screenshot for %s: %s", candidate, exc)
            return False
        finally:
            if page is not None:
                try:
                    await page.close()
                except Exception:
                    pass
            if context is not None:
                try:
                    await context.close()
                except Exception:
                    pass

    async def _run_ocr_second_pass(
        self,
        browser: Any,
        domain: str,
        crawl: CrawlResult,
        initial_risk_score: float,
        initial_status: str,
    ) -> Dict[str, Any]:
        details: Dict[str, Any] = {
            "attempted": True,
            "applied": False,
            "initial_status": initial_status,
            "initial_risk_score": round(initial_risk_score, 6),
            "final_risk_score": round(initial_risk_score, 6),
            "selected_url": "",
            "screenshot_path": "",
            "ocr_available": bool(self.ocr_processor and self.ocr_processor.available),
            "scores": None,
            "error": None,
            "history_path": "",
        }

        if self.ocr_processor is None or self.ocr_scorer is None:
            details["error"] = "ocr_components_unavailable"
            return details
        if not self.ocr_processor.available:
            details["error"] = "tesseract_unavailable"
            return details

        event_timestamp = utc_now()
        timestamp_token = event_timestamp.replace(":", "").replace("-", "").replace(".", "")
        screenshot_partition = event_timestamp[:10]
        screenshot_path = self.ocr_screenshot_dir / screenshot_partition / f"{domain.replace('.', '_')}_{timestamp_token}.png"
        screenshot_ok = False
        selected_url = ""

        for candidate_url in self._ocr_candidate_urls(domain, crawl):
            screenshot_ok = await self._capture_screenshot_with_browser(
                browser=browser,
                url=candidate_url,
                output_path=str(screenshot_path),
                timeout=30_000,
            )
            if screenshot_ok:
                selected_url = candidate_url
                break

        details["selected_url"] = selected_url
        details["screenshot_path"] = str(screenshot_path)

        if not screenshot_ok:
            details["error"] = "screenshot_capture_failed"
            return details

        dom_text = self.normalize_text(crawl.text or crawl.title or domain)
        ocr_text, ocr_confidence = self.ocr_processor.extract_text_from_screenshot(str(screenshot_path))
        ocr_scores = self.ocr_scorer.score_combined_text(dom_text, ocr_text, ocr_confidence)
        ocr_risk = clamp(float(ocr_scores.get("combined_score", 0.0)) / 10.0)

        final_risk = max(initial_risk_score, ocr_risk)
        details["final_risk_score"] = round(final_risk, 6)
        details["scores"] = {
            "ocr_dom_score": ocr_scores.get("dom_score"),
            "ocr_text_score": ocr_scores.get("ocr_score"),
            "ocr_combined_score": ocr_scores.get("combined_score"),
            "ocr_confidence": ocr_scores.get("ocr_confidence"),
            "ocr_verdict": ocr_scores.get("verdict"),
        }

        if final_risk > initial_risk_score:
            details["applied"] = True

        history_payload = {
            "timestamp": event_timestamp,
            "domain": domain,
            "selected_url": selected_url,
            "initial_status": initial_status,
            "initial_risk_score": round(initial_risk_score, 6),
            "final_risk_score": round(final_risk, 6),
            "applied": bool(details["applied"]),
            "scores": details["scores"],
            "ocr_text_length": len(ocr_text),
            "screenshot_path": str(screenshot_path),
        }
        details["history_path"] = self._write_ocr_history(domain, history_payload)
        return details

    def load_candidates(self) -> List[str]:
        if self.single_domain:
            self.domain_sources = {self.single_domain: ["user_report"]}
            return [self.single_domain]

        if self.test_mode:
            fixture_domains = [
                "slotgacor99.com",
                "gamingnews.id",
                "bandarmaxwin777.net",
                "forum-edukasi.org",
            ]
            self.domain_sources = {
                "slotgacor99.com": ["google_dorking", "platform_abuse_sweep"],
                "gamingnews.id": ["government_scanning"],
                "bandarmaxwin777.net": ["curated_gambling_feeds"],
                "forum-edukasi.org": ["osint_community"],
            }
            return fixture_domains

        if not self.input_file.exists():
            logger.warning("input file missing: %s", self.input_file)
            self.domain_sources = {}
            return []

        with self.input_file.open("r", encoding="utf-8") as fh:
            data = json.load(fh)

        domains: List[str] = []
        if isinstance(data, dict):
            raw = data.get("domains") or data.get("merged_domains") or []
            if isinstance(raw, list):
                domains = [str(d).strip().lower() for d in raw if str(d).strip()]

        if self.limit is not None:
            domains = domains[: self.limit]

        deduped: List[str] = []
        seen = set()
        for domain in domains:
            if domain in seen:
                continue
            seen.add(domain)
            deduped.append(domain)

        self._load_domain_sources_from_input()
        for domain in deduped:
            if domain not in self.domain_sources:
                self.domain_sources[domain] = ["unknown"]

        return deduped

    @staticmethod
    def normalize_text(text: str) -> str:
        if not text:
            return ""
        normalized = " ".join(text.split())
        return normalized[:6000]

    async def crawl_domain(self, browser: Any, domain: str) -> CrawlResult:
        # Always use a fresh context and close it to avoid memory leaks.
        context = await browser.new_context(
            viewport={"width": 1280, "height": 720},
            ignore_https_errors=True,
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
            ),
        )

        try:
            page = await context.new_page()
            target_urls = [f"https://{domain}", f"http://{domain}"]

            last_error: Optional[str] = None
            for target in target_urls:
                try:
                    await page.goto(target, wait_until="domcontentloaded", timeout=30_000)
                    title = await page.title()
                    text = await page.evaluate("() => document.body ? document.body.innerText : ''")
                    title = self.normalize_text(title or "")
                    text = self.normalize_text(text or "")
                    links = await page.eval_on_selector_all(
                        "a[href]",
                        "els => els.slice(0, 50).map(el => el.href)",
                    )
                    final_url = page.url
                    return CrawlResult(
                        domain=domain,
                        ok=True,
                        final_url=final_url,
                        title=title or "",
                        text=text or "",
                        links=links or [],
                        error=None,
                    )
                except PlaywrightTimeoutError:
                    last_error = "timeout"
                except Exception as exc:
                    last_error = str(exc)

            return CrawlResult(
                domain=domain,
                ok=False,
                final_url="",
                title="",
                text="",
                links=[],
                error=last_error or "unknown error",
            )
        finally:
            await context.close()

    def quality_adjustments(
        self,
        crawl: CrawlResult,
        heuristic: Dict[str, Any],
        ai_score: Optional[float],
    ) -> Tuple[float, float]:
        factor = 1.0
        bonus = 0.0

        text_len = len(crawl.text)
        links_len = len(crawl.links)
        danger_signal = len(heuristic.get("danger_hits", {}))
        safe_signal = len(heuristic.get("safe_hits", {}))
        payment_hits = int(heuristic.get("payment_hits", 0))
        messaging_hits = int(heuristic.get("messaging_hits", 0))

        if not crawl.ok:
            factor *= 0.86

        if text_len < self.min_text_length:
            factor *= 0.82
        elif text_len < 400:
            factor *= 0.92

        if links_len == 0:
            factor *= 0.95

        if ai_score is None:
            factor *= 0.93

        if payment_hits + messaging_hits >= 2:
            bonus += 0.03
        if danger_signal >= 4:
            bonus += 0.02
        if safe_signal > danger_signal and danger_signal < 2:
            bonus -= 0.03

        return factor, bonus

    def combine_scores(
        self,
        heuristic_score: float,
        ai_score: Optional[float],
        quality_factor: float,
        quality_bonus: float,
    ) -> float:
        if ai_score is None:
            combined = heuristic_score
        else:
            combined = (ai_score * self.ai_weight) + (heuristic_score * self.heuristic_weight)

        return clamp((combined * quality_factor) + quality_bonus)

    def verdict_from_score(self, score: float) -> Dict[str, Any]:
        gambling = self.thresholds["gambling"]
        suspicious = self.thresholds["suspicious"]
        borderline = self.thresholds["borderline"]

        if score >= gambling:
            return {"status": "GAMBLING", "confidence": score * 100.0}
        if score >= suspicious:
            return {"status": "SUSPICIOUS", "confidence": score * 100.0}
        if score >= borderline:
            return {"status": "BORDERLINE", "confidence": score * 100.0}
        return {"status": "SAFE", "confidence": (1.0 - score) * 100.0}

    async def _verify_one(self, browser: Any, semaphore: asyncio.Semaphore, domain: str) -> Dict[str, Any]:
        async with semaphore:
            crawl = await self.crawl_domain(browser, domain)

            text_for_scoring = crawl.text
            title_for_scoring = crawl.title
            if not crawl.ok and self.test_mode:
                # Offline fallback fixture for quick test mode.
                text_for_scoring = f"{domain} slot gacor deposit withdraw"
                title_for_scoring = f"{domain}"

            heuristic = self.scorer.score(text_for_scoring, title_for_scoring, crawl.links)
            heuristic_score = float(heuristic["score"])

            ai_input = "\n".join([title_for_scoring, text_for_scoring])
            ai_details = self.ai.score(ai_input)
            ai_score = None if ai_details is None else float(ai_details["calibrated"])

            quality_factor, quality_bonus = self.quality_adjustments(crawl, heuristic, ai_score)

            combined = self.combine_scores(
                heuristic_score=heuristic_score,
                ai_score=ai_score,
                quality_factor=quality_factor,
                quality_bonus=quality_bonus,
            )
            source_multiplier, source_methods, source_method_weights = self._source_multiplier_for_domain(domain)
            combined = clamp(combined * source_multiplier)
            initial_verdict = self.verdict_from_score(combined)

            ocr_details: Dict[str, Any] = {
                "attempted": False,
                "applied": False,
                "initial_status": initial_verdict["status"],
                "initial_risk_score": round(combined, 6),
                "final_risk_score": round(combined, 6),
                "selected_url": "",
                "screenshot_path": "",
                "ocr_available": bool(self.ocr_processor and self.ocr_processor.available),
                "scores": None,
                "error": None,
                "history_path": "",
            }

            if self._should_run_ocr_second_pass(
                status=initial_verdict["status"],
                confidence=float(initial_verdict["confidence"]),
                crawl=crawl,
            ):
                try:
                    ocr_details = await self._run_ocr_second_pass(
                        browser=browser,
                        domain=domain,
                        crawl=crawl,
                        initial_risk_score=combined,
                        initial_status=initial_verdict["status"],
                    )
                    combined = float(ocr_details.get("final_risk_score", combined))
                except Exception as exc:
                    ocr_details = {
                        **ocr_details,
                        "attempted": True,
                        "error": f"ocr_second_pass_error: {exc}",
                    }

            verdict = self.verdict_from_score(combined)

            return {
                "domain": domain,
                "source_methods": source_methods,
                "status": verdict["status"],
                "confidence": round(float(verdict["confidence"]), 3),
                "risk_score": round(combined, 6),
                "analysis": {
                    "heuristic_score": round(heuristic_score, 6),
                    "ai_score": None if ai_score is None else round(float(ai_score), 6),
                    "ai_raw_max": None if ai_details is None else ai_details["raw_max"],
                    "ai_topk_mean": None if ai_details is None else ai_details["topk_mean"],
                    "initial_combined_score": round(float(ocr_details.get("initial_risk_score", combined)), 6),
                    "combined_score": round(combined, 6),
                    "quality_factor": round(quality_factor, 6),
                    "quality_bonus": round(quality_bonus, 6),
                    "danger_hits": heuristic["danger_hits"],
                    "safe_hits": heuristic["safe_hits"],
                    "payment_hits": heuristic["payment_hits"],
                    "messaging_hits": heuristic["messaging_hits"],
                    "weights": {
                        "ai": round(self.ai_weight, 4),
                        "heuristic": round(self.heuristic_weight, 4),
                    },
                    "source_calibration": {
                        "enabled": self.source_calibration_enabled,
                        "multiplier": round(source_multiplier, 6),
                        "by_method": source_method_weights,
                    },
                    "thresholds": self.thresholds,
                    "ai_model": self.ai.model_name if self.ai.enabled else "heuristic_fallback",
                    "ocr_second_pass": ocr_details,
                },
                "crawl": {
                    "ok": crawl.ok,
                    "final_url": crawl.final_url,
                    "title": crawl.title,
                    "error": crawl.error,
                    "text_length": len(crawl.text),
                    "links": len(crawl.links),
                },
            }

    async def verify(self) -> Dict[str, Any]:
        self._prune_ocr_history()
        self._load_calibration_profile()
        self._auto_calibrate_thresholds()
        self._load_source_calibration_profile()

        domains = self.load_candidates()
        if not domains:
            logger.warning("no domains to verify")
            payload = {
                "timestamp": utc_now(),
                "total_input": 0,
                "total_verified": 0,
                "statistics": {"GAMBLING": 0, "SUSPICIOUS": 0, "BORDERLINE": 0, "SAFE": 0, "UNKNOWN": 0},
                "metrics": {
                    "average_risk_score": 0.0,
                    "average_confidence": 0.0,
                    "crawl_failures": 0,
                },
                "config": {
                    "workers": self.workers,
                    "thresholds": self.thresholds,
                    "weights": {
                        "ai": round(self.ai_weight, 4),
                        "heuristic": round(self.heuristic_weight, 4),
                    },
                    "min_text_length": self.min_text_length,
                    "single_domain": self.single_domain or None,
                    "require_ai": self.require_ai,
                    "ai_enabled": self.ai.enabled,
                    "ocr_second_pass": {
                        "enabled": self.ocr_enabled,
                        "trigger_statuses": sorted(self.ocr_trigger_statuses),
                        "confidence_threshold": self.ocr_confidence_threshold,
                        "screenshot_dir": str(self.ocr_screenshot_dir),
                        "threshold_profile": str(self.ocr_threshold_profile),
                        "history_dir": str(self.ocr_history_dir),
                        "history_retention_days": self.ocr_history_retention_days,
                    },
                    "calibration": self.calibration_report,
                    "source_calibration": {
                        "enabled": self.source_calibration_enabled,
                        "profile": str(self.source_calibration_profile),
                        "source_count": len(self.source_multipliers),
                    },
                },
                "domains": [],
            }
            self.write_output(payload)
            return payload

        if not PLAYWRIGHT_AVAILABLE and not self.test_mode:
            raise RuntimeError("playwright unavailable in production mode")

        results: List[Dict[str, Any]] = []

        if PLAYWRIGHT_AVAILABLE:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=[
                        "--disable-dev-shm-usage",
                        "--single-process=false",
                        "--disable-gpu",
                        "--no-sandbox",
                    ],
                )
                try:
                    sem = asyncio.Semaphore(self.workers)
                    tasks = [self._verify_one(browser, sem, d) for d in domains]
                    gathered = await asyncio.gather(*tasks, return_exceptions=True)
                    for domain, item in zip(domains, gathered):
                        source_multiplier, source_methods, source_method_weights = self._source_multiplier_for_domain(domain)
                        if isinstance(item, Exception):
                            results.append(
                                {
                                    "domain": domain,
                                    "source_methods": source_methods,
                                    "status": "UNKNOWN",
                                    "confidence": 0.0,
                                    "risk_score": 0.0,
                                    "analysis": {
                                        "heuristic_score": 0.0,
                                        "ai_score": None,
                                        "ai_raw_max": None,
                                        "ai_topk_mean": None,
                                        "initial_combined_score": 0.0,
                                        "combined_score": 0.0,
                                        "quality_factor": 0.0,
                                        "quality_bonus": 0.0,
                                        "danger_hits": {},
                                        "safe_hits": {},
                                        "payment_hits": 0,
                                        "messaging_hits": 0,
                                        "weights": {
                                            "ai": round(self.ai_weight, 4),
                                            "heuristic": round(self.heuristic_weight, 4),
                                        },
                                        "source_calibration": {
                                            "enabled": self.source_calibration_enabled,
                                            "multiplier": round(source_multiplier, 6),
                                            "by_method": source_method_weights,
                                        },
                                        "thresholds": self.thresholds,
                                        "ai_model": self.ai.model_name if self.ai.enabled else "heuristic_fallback",
                                        "ocr_second_pass": {
                                            "attempted": False,
                                            "applied": False,
                                            "initial_status": "UNKNOWN",
                                            "initial_risk_score": 0.0,
                                            "final_risk_score": 0.0,
                                            "selected_url": "",
                                            "screenshot_path": "",
                                            "ocr_available": bool(self.ocr_processor and self.ocr_processor.available),
                                            "scores": None,
                                            "error": "verification_exception",
                                            "history_path": "",
                                        },
                                    },
                                    "crawl": {
                                        "ok": False,
                                        "final_url": "",
                                        "title": "",
                                        "error": str(item),
                                        "text_length": 0,
                                        "links": 0,
                                    },
                                }
                            )
                        else:
                            results.append(item)
                finally:
                    await browser.close()
        else:
            for domain in domains:
                source_multiplier, source_methods, source_method_weights = self._source_multiplier_for_domain(domain)
                heuristic = self.scorer.score(domain, domain, [])
                score = float(heuristic["score"])
                quality_factor, quality_bonus = self.quality_adjustments(
                    CrawlResult(
                        domain=domain,
                        ok=False,
                        final_url="",
                        title=domain,
                        text=domain,
                        links=[],
                        error="playwright unavailable",
                    ),
                    heuristic,
                    None,
                )
                calibrated_score = self.combine_scores(score, None, quality_factor, quality_bonus)
                calibrated_score = clamp(calibrated_score * source_multiplier)
                verdict = self.verdict_from_score(calibrated_score)
                results.append(
                    {
                        "domain": domain,
                        "source_methods": source_methods,
                        "status": verdict["status"],
                        "confidence": round(float(verdict["confidence"]), 3),
                        "risk_score": round(calibrated_score, 6),
                        "analysis": {
                            "heuristic_score": round(score, 6),
                            "ai_score": None,
                            "ai_raw_max": None,
                            "ai_topk_mean": None,
                            "initial_combined_score": round(score, 6),
                            "combined_score": round(calibrated_score, 6),
                            "quality_factor": round(quality_factor, 6),
                            "quality_bonus": round(quality_bonus, 6),
                            "danger_hits": heuristic["danger_hits"],
                            "safe_hits": heuristic["safe_hits"],
                            "payment_hits": 0,
                            "messaging_hits": 0,
                            "weights": {
                                "ai": round(self.ai_weight, 4),
                                "heuristic": round(self.heuristic_weight, 4),
                            },
                            "source_calibration": {
                                "enabled": self.source_calibration_enabled,
                                "multiplier": round(source_multiplier, 6),
                                "by_method": source_method_weights,
                            },
                            "thresholds": self.thresholds,
                            "ai_model": "heuristic_only",
                            "ocr_second_pass": {
                                "attempted": False,
                                "applied": False,
                                "initial_status": verdict["status"],
                                "initial_risk_score": round(calibrated_score, 6),
                                "final_risk_score": round(calibrated_score, 6),
                                "selected_url": "",
                                "screenshot_path": "",
                                "ocr_available": bool(self.ocr_processor and self.ocr_processor.available),
                                "scores": None,
                                "error": "playwright_unavailable",
                                "history_path": "",
                            },
                        },
                        "crawl": {
                            "ok": False,
                            "final_url": "",
                            "title": "",
                            "error": "playwright unavailable",
                            "text_length": 0,
                            "links": 0,
                        },
                    }
                )

        stats = {"GAMBLING": 0, "SUSPICIOUS": 0, "BORDERLINE": 0, "SAFE": 0, "UNKNOWN": 0}
        confidence_values: List[float] = []
        risk_values: List[float] = []
        crawl_failures = 0

        for item in results:
            status = item.get("status", "UNKNOWN")
            if status not in stats:
                status = "UNKNOWN"
            stats[status] += 1

            confidence_values.append(float(item.get("confidence", 0.0)))
            risk_values.append(float(item.get("risk_score", 0.0)))
            crawl_ok = bool(item.get("crawl", {}).get("ok", False))
            if not crawl_ok:
                crawl_failures += 1

        avg_confidence = (sum(confidence_values) / len(confidence_values)) if confidence_values else 0.0
        avg_risk = (sum(risk_values) / len(risk_values)) if risk_values else 0.0

        payload = {
            "timestamp": utc_now(),
            "total_input": len(domains),
            "total_verified": len(results),
            "statistics": stats,
            "metrics": {
                "average_risk_score": round(avg_risk, 6),
                "average_confidence": round(avg_confidence, 3),
                "crawl_failures": crawl_failures,
            },
            "config": {
                "workers": self.workers,
                "thresholds": self.thresholds,
                "weights": {
                    "ai": round(self.ai_weight, 4),
                    "heuristic": round(self.heuristic_weight, 4),
                },
                "min_text_length": self.min_text_length,
                "single_domain": self.single_domain or None,
                "require_ai": self.require_ai,
                "ai_enabled": self.ai.enabled,
                "ocr_second_pass": {
                    "enabled": self.ocr_enabled,
                    "trigger_statuses": sorted(self.ocr_trigger_statuses),
                    "confidence_threshold": self.ocr_confidence_threshold,
                    "screenshot_dir": str(self.ocr_screenshot_dir),
                    "threshold_profile": str(self.ocr_threshold_profile),
                    "history_dir": str(self.ocr_history_dir),
                    "history_retention_days": self.ocr_history_retention_days,
                },
                "calibration": self.calibration_report,
                "source_calibration": {
                    "enabled": self.source_calibration_enabled,
                    "profile": str(self.source_calibration_profile),
                    "source_count": len(self.source_multipliers),
                },
            },
            "domains": results,
        }

        self.write_output(payload)
        return payload

    def write_output(self, payload: Dict[str, Any]) -> None:
        self.output_file.parent.mkdir(parents=True, exist_ok=True)
        with self.output_file.open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        logger.info("verification written to %s", self.output_file)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run anti-judol domain verifier")
    parser.add_argument(
        "--input",
        default=str(DATA_DIR / "candidates_merged.json"),
        help="Path to candidates_merged.json",
    )
    parser.add_argument(
        "--output",
        default=str(DATA_DIR / "verified_domains.json"),
        help="Path to write verified domains",
    )
    parser.add_argument("--workers", type=int, default=4, help="Playwright concurrent workers")
    parser.add_argument("--limit", type=int, default=None, help="Optional max number of domains")
    parser.add_argument("--single-domain", default="", help="Run verification only for one domain or URL")
    parser.add_argument("--ai-weight", type=float, default=0.60, help="Weight for AI score in blending")
    parser.add_argument("--heuristic-weight", type=float, default=0.40, help="Weight for heuristic score in blending")
    parser.add_argument("--gambling-threshold", type=float, default=0.75, help="Threshold for GAMBLING verdict")
    parser.add_argument("--suspicious-threshold", type=float, default=0.55, help="Threshold for SUSPICIOUS verdict")
    parser.add_argument("--borderline-threshold", type=float, default=0.35, help="Threshold for BORDERLINE verdict")
    parser.add_argument("--min-text-length", type=int, default=120, help="Minimum extracted text length before confidence penalty")
    parser.add_argument(
        "--calibration-samples",
        default=str(DATA_DIR / "calibration_samples.json"),
        help="JSON file with labeled score samples for auto calibration",
    )
    parser.add_argument(
        "--calibration-profile",
        default=str(DATA_DIR / "threshold_profile.json"),
        help="Optional profile JSON for thresholds/weights",
    )
    parser.add_argument(
        "--disable-auto-calibration",
        action="store_true",
        help="Disable threshold auto calibration from sample file",
    )
    parser.add_argument(
        "--disable-ocr-second-pass",
        action="store_true",
        help="Disable OCR second-pass for suspicious or low-confidence domains",
    )
    parser.add_argument(
        "--ocr-trigger-statuses",
        default="SUSPICIOUS,BORDERLINE,UNKNOWN",
        help="Comma-separated statuses that trigger OCR second-pass",
    )
    parser.add_argument(
        "--ocr-confidence-threshold",
        type=float,
        default=70.0,
        help="Run OCR second-pass when confidence is below this value (0-100)",
    )
    parser.add_argument(
        "--ocr-screenshot-dir",
        default=str(DATA_DIR / "screenshots"),
        help="Directory to store OCR screenshots",
    )
    parser.add_argument(
        "--ocr-threshold-profile",
        default=str(DATA_DIR / "threshold_profile_ocr.json"),
        help="OCR threshold profile JSON path",
    )
    parser.add_argument(
        "--ocr-history-dir",
        default=str(DATA_DIR / "ocr-history"),
        help="Directory to store append-only OCR history",
    )
    parser.add_argument(
        "--ocr-history-retention-days",
        type=int,
        default=30,
        help="Retention period (days) for OCR history partition folders",
    )
    parser.add_argument(
        "--source-calibration-profile",
        default=str(DATA_DIR / "source_calibration_profile.json"),
        help="Per-source score calibration profile JSON path",
    )
    parser.add_argument(
        "--disable-source-calibration",
        action="store_true",
        help="Disable per-source score multiplier calibration",
    )
    parser.add_argument(
        "--require-ai",
        action="store_true",
        help="Fail run when sentence-transformer model is unavailable",
    )
    parser.add_argument("--test", action="store_true", help="Run with local fixture domains")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    verifier = DomainVerifier(
        input_file=Path(args.input),
        output_file=Path(args.output),
        workers=args.workers,
        test_mode=args.test,
        limit=args.limit,
        single_domain=args.single_domain,
        ai_weight=args.ai_weight,
        heuristic_weight=args.heuristic_weight,
        gambling_threshold=args.gambling_threshold,
        suspicious_threshold=args.suspicious_threshold,
        borderline_threshold=args.borderline_threshold,
        min_text_length=args.min_text_length,
        calibration_samples=Path(args.calibration_samples),
        calibration_profile=Path(args.calibration_profile),
        auto_calibration=not args.disable_auto_calibration,
        enable_ocr_second_pass=not args.disable_ocr_second_pass,
        ocr_trigger_statuses=args.ocr_trigger_statuses,
        ocr_confidence_threshold=args.ocr_confidence_threshold,
        ocr_screenshot_dir=Path(args.ocr_screenshot_dir),
        ocr_threshold_profile=Path(args.ocr_threshold_profile),
        ocr_history_dir=Path(args.ocr_history_dir),
        ocr_history_retention_days=args.ocr_history_retention_days,
        source_calibration_profile=Path(args.source_calibration_profile),
        disable_source_calibration=args.disable_source_calibration,
        require_ai=args.require_ai,
    )
    asyncio.run(verifier.verify())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
