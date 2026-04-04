#!/usr/bin/env python3
"""OCR processor utilities for screenshot text extraction."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Tuple

try:
    import pytesseract
except Exception:  # pragma: no cover - dependency availability varies by environment.
    pytesseract = None

try:
    from PIL import Image
except Exception:  # pragma: no cover - dependency availability varies by environment.
    Image = None


logger = logging.getLogger("ocr_processor")


def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


class OCRProcessor:
    """Extract text from image files using Tesseract."""

    def __init__(self, lang: str = "ind+eng") -> None:
        self.lang = lang
        self._available = False
        self._verify_tesseract()

    @property
    def available(self) -> bool:
        return self._available

    def _verify_tesseract(self) -> None:
        if pytesseract is None or Image is None:
            logger.warning("pytesseract or Pillow not available; OCR disabled")
            self._available = False
            return

        try:
            _ = pytesseract.pytesseract.get_tesseract_version()
            self._available = True
        except Exception as exc:
            logger.warning("tesseract not available; OCR fallback enabled: %s", exc)
            self._available = False

    @staticmethod
    def _parse_confidence(values: Any) -> float:
        parsed = []
        for value in values or []:
            try:
                score = float(value)
            except Exception:
                continue
            if score >= 0:
                parsed.append(score)

        if not parsed:
            return 0.0

        return clamp((sum(parsed) / len(parsed)) / 100.0)

    def extract_text_from_screenshot(self, screenshot_path: str) -> Tuple[str, float]:
        """Return tuple: (ocr_text, average_confidence_0_to_1)."""
        if not self._available or pytesseract is None or Image is None:
            return "", 0.0

        path = Path(screenshot_path)
        if not path.exists() or not path.is_file():
            logger.warning("screenshot missing: %s", screenshot_path)
            return "", 0.0

        try:
            image = Image.open(path)
            data = pytesseract.image_to_data(
                image,
                lang=self.lang,
                output_type=pytesseract.Output.DICT,
            )
            confidence = self._parse_confidence(data.get("conf", []))
            text = pytesseract.image_to_string(image, lang=self.lang)
            text = " ".join(str(text).split())
            return text, confidence
        except Exception as exc:
            logger.warning("ocr extraction failed for %s: %s", screenshot_path, exc)
            return "", 0.0
