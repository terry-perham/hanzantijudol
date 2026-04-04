#!/usr/bin/env python3
"""Playwright-based screenshot capture helper."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

try:
    from playwright.async_api import TimeoutError as PlaywrightTimeoutError
    from playwright.async_api import async_playwright

    PLAYWRIGHT_AVAILABLE = True
except Exception:  # pragma: no cover - dependency availability varies by environment.
    PlaywrightTimeoutError = Exception
    async_playwright = None
    PLAYWRIGHT_AVAILABLE = False


logger = logging.getLogger("screenshot_capture")


class ScreenshotCapture:
    """Capture full-page screenshots with safe cleanup."""

    @staticmethod
    def _normalize_url(url: str) -> str:
        candidate = (url or "").strip()
        if not candidate:
            return ""
        if not candidate.startswith("http://") and not candidate.startswith("https://"):
            candidate = f"https://{candidate}"
        return candidate

    @staticmethod
    def _is_valid_url(url: str) -> bool:
        try:
            parsed = urlparse(url)
            return bool(parsed.scheme and parsed.netloc)
        except Exception:
            return False

    async def capture_screenshot(self, url: str, output_path: str, timeout: int = 30_000) -> bool:
        """Capture screenshot and return True on success, False otherwise."""
        normalized_url = self._normalize_url(url)
        if not self._is_valid_url(normalized_url):
            logger.warning("invalid url for screenshot: %s", url)
            return False

        if not PLAYWRIGHT_AVAILABLE or async_playwright is None:
            logger.warning("playwright unavailable; screenshot disabled")
            return False

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        async with async_playwright() as p:
            browser: Any = None
            context: Any = None
            page: Any = None
            try:
                browser = await p.chromium.launch(
                    headless=True,
                    args=[
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                        "--single-process=false",
                        "--no-sandbox",
                    ],
                )
                context = await browser.new_context(viewport={"width": 1280, "height": 720})
                page = await context.new_page()

                try:
                    await page.goto(normalized_url, wait_until="domcontentloaded", timeout=timeout)
                except PlaywrightTimeoutError:
                    logger.warning("page timeout while capturing screenshot: %s", normalized_url)
                except Exception as exc:
                    logger.warning("navigation error while capturing screenshot (%s): %s", normalized_url, exc)

                await asyncio.sleep(2)
                await page.screenshot(path=str(path), full_page=True)
                return True
            except Exception as exc:
                logger.warning("failed to capture screenshot for %s: %s", normalized_url, exc)
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
                if browser is not None:
                    try:
                        await browser.close()
                    except Exception:
                        pass
