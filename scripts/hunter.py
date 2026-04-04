#!/usr/bin/env python3
"""Domain hunting pipeline (Methods A-F).

Phases covered:
- Phase 1: skeleton/orchestrator
- Phase 2: Google dorking (Selenium)
- Phase 3: CT logs (Censys + fallback)
- Phase 4: Government scanning (.go.id / .ac.id)
- Phase 5: OSINT/community aggregation
- Phase 6: consolidation and deduplication
- Phase 7: curated gambling feeds ingestion
- Phase 8: platform abuse sweep
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import logging
import os
import random
import re
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set
from urllib.parse import quote_plus, unquote, urlparse

import aiohttp
from bs4 import BeautifulSoup
from dotenv import load_dotenv

try:
    from selenium import webdriver
    from selenium.common.exceptions import TimeoutException, WebDriverException
    from selenium.webdriver.chrome.options import Options

    SELENIUM_AVAILABLE = True
except Exception:
    SELENIUM_AVAILABLE = False


load_dotenv()

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("hunter")


DOMAIN_REGEX = re.compile(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def utc_now() -> str:
    return datetime.utcnow().isoformat() + "Z"


def ensure_data_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def normalize_domain(domain: str) -> Optional[str]:
    if not domain:
        return None

    d = domain.strip().lower().rstrip(".")
    if d.startswith("www."):
        d = d[4:]
    return d


def is_valid_domain(domain: Optional[str]) -> bool:
    if not domain:
        return False

    d = normalize_domain(domain)
    if not d:
        return False

    if len(d) < 3 or len(d) > 255:
        return False

    if d.startswith("*."):
        return False

    if d.endswith(".local") or d.endswith(".internal"):
        return False

    return bool(DOMAIN_REGEX.match(d))


def extract_domain_from_url(value: str) -> Optional[str]:
    if not value:
        return None

    text = value.strip()
    if text.startswith("//"):
        text = "https:" + text

    if not text.startswith("http://") and not text.startswith("https://"):
        text = "https://" + text

    try:
        parsed = urlparse(text)
        return normalize_domain(parsed.netloc)
    except Exception:
        return None


def parse_hosts_or_domain_line(value: str) -> Optional[str]:
    if not value:
        return None

    row = value.strip()
    if not row or row.startswith("#") or row.startswith("!"):
        return None

    if row.startswith("||"):
        row = row.replace("||", "", 1).split("^")[0].strip()

    chunks = row.split()
    if len(chunks) >= 2 and chunks[0] in {"0.0.0.0", "127.0.0.1", "::", "::1"}:
        row = chunks[1]
    elif len(chunks) == 1:
        row = chunks[0]
    else:
        row = chunks[-1]

    row = row.strip()
    if row.startswith("http://") or row.startswith("https://"):
        return extract_domain_from_url(row)

    return normalize_domain(row)


def is_platform_host(domain: Optional[str], platform_suffixes: Iterable[str]) -> bool:
    if not domain:
        return False

    value = normalize_domain(domain)
    if not value:
        return False

    for suffix in platform_suffixes:
        suffix_norm = normalize_domain(suffix or "")
        if not suffix_norm:
            continue
        if value == suffix_norm or value.endswith(f".{suffix_norm}"):
            return True
    return False


def looks_like_gambling_text(value: str) -> bool:
    text = (value or "").lower()
    if not text:
        return False

    tokens = (
        "slot",
        "judi",
        "togel",
        "gacor",
        "maxwin",
        "rtp",
        "jackpot",
        "bet",
        "depo",
        "taruhan",
    )
    return any(token in text for token in tokens)


def looks_like_gambling_domain(domain: Optional[str]) -> bool:
    value = normalize_domain(domain or "")
    if not value:
        return False

    # Domain-label heuristics improve recall for platform abuse mirrors
    # where search URL/title text may not include obvious gambling terms.
    tokens = (
        "slot",
        "judi",
        "togel",
        "rtp",
        "maxwin",
        "gacor",
        "jackpot",
        "bet",
        "casino",
        "depo",
        "wd",
    )
    labels = value.replace("-", ".").split(".")
    joined = " ".join(labels)
    return any(token in joined for token in tokens)


def build_connector() -> aiohttp.TCPConnector:
    return aiohttp.TCPConnector(
        limit=100,
        limit_per_host=10,
        ttl_dns_cache=600,
        use_dns_cache=True,
        keepalive_timeout=30,
        force_close=False,
    )


def build_timeout() -> aiohttp.ClientTimeout:
    return aiohttp.ClientTimeout(total=30, connect=10, sock_read=15)


class HuntingMethod(ABC):
    """Base contract for each hunting method."""

    @abstractmethod
    def get_method_name(self) -> str:
        pass

    @abstractmethod
    def get_output_file(self) -> Path:
        pass

    @abstractmethod
    async def hunt(self) -> Set[str]:
        pass


class MethodA(HuntingMethod):
    """Google dorking with Selenium."""

    KEYWORDS = [
        "slot gacor",
        "situs judi",
        "togel prediksi",
        "betting online",
        "mahjong ways",
        "rtp live",
        "toto togel",
        "slots terpercaya",
        "agen slot",
        "pragmatic play",
    ]

    TLDS = [".com", ".net", ".xyz", ".info", ".site"]

    SKIP_DOMAINS = {
        "google.com",
        "facebook.com",
        "reddit.com",
        "wikipedia.org",
        "github.com",
        "youtube.com",
    }

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    ]

    def __init__(self, test_mode: bool = False) -> None:
        self.test_mode = test_mode
        self.candidates: Set[str] = set()
        self.browser: Any = None

    def get_method_name(self) -> str:
        return "google_dorking"

    def get_output_file(self) -> Path:
        return DATA_DIR / "candidates_a.json"

    def _construct_query(self, keyword: str) -> str:
        tld_clause = " OR ".join([f"site:{tld}" for tld in self.TLDS])
        return f'"{keyword}" {tld_clause}'

    def _init_browser(self) -> None:
        if not SELENIUM_AVAILABLE:
            raise RuntimeError("selenium is not installed or not available")

        options = Options()
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_argument("--window-size=1366,768")
        options.add_argument(f"--user-agent={random.choice(self.USER_AGENTS)}")
        self.browser = webdriver.Chrome(options=options)

    def _close_browser(self) -> None:
        if self.browser:
            try:
                self.browser.quit()
            except Exception:
                pass
            finally:
                self.browser = None

    async def _search_google(self, keyword: str) -> List[str]:
        query = self._construct_query(keyword)
        url = f"https://www.google.com/search?q={quote_plus(query)}&num=20"

        self.browser.get(url)
        await asyncio.sleep(random.uniform(2.0, 4.0))

        links = self.browser.find_elements("css selector", "a[href]")
        urls: List[str] = []

        for link in links:
            href = link.get_attribute("href") or ""
            if "/url?q=" not in href:
                continue

            try:
                raw = href.split("/url?q=")[1].split("&")[0]
                urls.append(unquote(raw))
            except Exception:
                continue

        return urls

    async def _search_with_retry(self, keyword: str) -> List[str]:
        max_retries = 3
        for attempt in range(max_retries):
            try:
                return await self._search_google(keyword)
            except (TimeoutException, WebDriverException) as exc:
                if attempt >= max_retries - 1:
                    logger.warning("method_a keyword=%s failed after retries: %s", keyword, exc)
                    return []
                backoff = 2 ** attempt
                await asyncio.sleep(backoff)
            except Exception as exc:
                logger.warning("method_a keyword=%s unexpected error: %s", keyword, exc)
                return []
        return []

    async def hunt(self) -> Set[str]:
        logger.info("method_a started")

        if self.test_mode:
            # Offline test fixture for quick checks.
            self.candidates = {
                "slotgacor123.com",
                "judi-online-terbaik.net",
                "rtplive777.site",
            }
            self._save_results(duration=0.0)
            return self.candidates

        if not SELENIUM_AVAILABLE:
            logger.error("method_a skipped because selenium is unavailable")
            self._save_results(duration=0.0)
            return self.candidates

        start = time.perf_counter()
        keywords = self.KEYWORDS if not self.test_mode else self.KEYWORDS[:2]

        try:
            self._init_browser()

            for keyword in keywords:
                urls = await self._search_with_retry(keyword)
                for candidate_url in urls:
                    domain = extract_domain_from_url(candidate_url)
                    if not is_valid_domain(domain):
                        continue
                    if domain in self.SKIP_DOMAINS:
                        continue
                    if domain.endswith(".gov") or domain.endswith(".edu") or domain.endswith(".org"):
                        continue
                    self.candidates.add(domain)

                await asyncio.sleep(random.uniform(2.0, 4.0))

        finally:
            self._close_browser()

        duration = time.perf_counter() - start
        self._save_results(duration=duration)
        logger.info("method_a completed with %d domains", len(self.candidates))
        return self.candidates

    def _save_results(self, duration: float) -> None:
        payload = {
            "timestamp": utc_now(),
            "method": self.get_method_name(),
            "keywords_searched": len(self.KEYWORDS),
            "candidate_count": len(self.candidates),
            "time_seconds": round(duration, 3),
            "domains": sorted(self.candidates),
        }

        with self.get_output_file().open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)


class MethodB(HuntingMethod):
    """Certificate Transparency search."""

    KEYWORDS = ["slot", "gacor", "judi", "bet", "mahjong"]

    def __init__(self, test_mode: bool = False) -> None:
        self.test_mode = test_mode
        self.candidates: Set[str] = set()
        self.censys_id = os.getenv("CENSYS_API_ID", "")
        self.censys_secret = os.getenv("CENSYS_API_SECRET", "")

    def get_method_name(self) -> str:
        return "certificate_transparency"

    def get_output_file(self) -> Path:
        return DATA_DIR / "candidates_b.json"

    async def _fetch_censys(self, session: aiohttp.ClientSession, keyword: str) -> List[Dict[str, Any]]:
        endpoint = "https://search.censys.io/api/v2/certificates/search"
        params = {"q": f"parsed.names: *{keyword}*", "per_page": 100}

        kwargs: Dict[str, Any] = {
            "params": params,
            "timeout": build_timeout(),
            "headers": {"User-Agent": "AntiJudolHunter/1.0"},
        }

        if self.censys_id and self.censys_secret:
            kwargs["auth"] = aiohttp.BasicAuth(self.censys_id, self.censys_secret)

        async with session.get(endpoint, **kwargs) as resp:
            if resp.status != 200:
                return []
            data = await resp.json(content_type=None)
            hits = data.get("result", {}).get("hits", [])
            parsed: List[Dict[str, Any]] = []
            for hit in hits:
                names = hit.get("names", [])
                for name in names:
                    parsed.append({"common_name": name})
            return parsed

    async def _fetch_crtsh(self, session: aiohttp.ClientSession, keyword: str) -> List[Dict[str, Any]]:
        endpoint = "https://crt.sh/"
        params = {"q": f"%{keyword}%", "output": "json"}
        async with session.get(endpoint, params=params, timeout=build_timeout()) as resp:
            if resp.status != 200:
                return []
            text = await resp.text()
            if not text.strip():
                return []
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return []

    def _extract_domain_from_cert(self, cert: Dict[str, Any]) -> Optional[str]:
        candidate = cert.get("common_name") or cert.get("name_value") or ""
        if not candidate:
            return None

        candidate = candidate.split("\n")[0].strip().lower()
        if candidate.startswith("*."):
            return None

        candidate = normalize_domain(candidate)
        if not is_valid_domain(candidate):
            return None
        return candidate

    async def hunt(self) -> Set[str]:
        logger.info("method_b started")

        if self.test_mode:
            self.candidates = {
                "slotbaru88.com",
                "judi-asia-net.net",
                "mahjongbet777.xyz",
            }
            self._save_results(duration=0.0)
            return self.candidates

        start = time.perf_counter()
        connector = build_connector()

        async with aiohttp.ClientSession(connector=connector, timeout=build_timeout()) as session:
            for keyword in self.KEYWORDS:
                certs: List[Dict[str, Any]] = []

                try:
                    certs = await self._fetch_censys(session, keyword)
                except Exception:
                    certs = []

                if not certs:
                    try:
                        certs = await self._fetch_crtsh(session, keyword)
                    except Exception:
                        certs = []

                for cert in certs:
                    domain = self._extract_domain_from_cert(cert)
                    if domain:
                        self.candidates.add(domain)

                await asyncio.sleep(1.0)

        await asyncio.sleep(0.250)

        duration = time.perf_counter() - start
        self._save_results(duration=duration)
        logger.info("method_b completed with %d domains", len(self.candidates))
        return self.candidates

    def _save_results(self, duration: float) -> None:
        payload = {
            "timestamp": utc_now(),
            "method": self.get_method_name(),
            "keywords_searched": len(self.KEYWORDS),
            "candidate_count": len(self.candidates),
            "time_seconds": round(duration, 3),
            "domains": sorted(self.candidates),
        }

        with self.get_output_file().open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)


class MethodC(HuntingMethod):
    """Government domain search with DuckDuckGo html endpoint."""

    TARGETS = [".go.id", ".ac.id"]
    KEYWORDS = ["slot", "gacor", "judi", "betting"]

    def __init__(self, test_mode: bool = False) -> None:
        self.test_mode = test_mode
        self.candidates: Set[str] = set()

    def get_method_name(self) -> str:
        return "government_scanning"

    def get_output_file(self) -> Path:
        return DATA_DIR / "candidates_c.json"

    async def _duckduckgo_search(self, session: aiohttp.ClientSession, query: str) -> List[str]:
        endpoint = "https://duckduckgo.com/html/"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"
        }

        async with session.get(
            endpoint,
            params={"q": query},
            headers=headers,
            timeout=build_timeout(),
        ) as resp:
            if resp.status != 200:
                return []
            html = await resp.text()

        soup = BeautifulSoup(html, "html.parser")
        hrefs: List[str] = []

        for tag in soup.select("a[href]"):
            href = tag.get("href", "")
            if not href:
                continue
            if href.startswith("/"):
                continue
            hrefs.append(href)

        return hrefs

    async def hunt(self) -> Set[str]:
        logger.info("method_c started")

        if self.test_mode:
            self.candidates = {
                "sample.go.id",
                "contoh.ac.id",
            }
            self._save_results(duration=0.0)
            return self.candidates

        start = time.perf_counter()
        connector = build_connector()

        async with aiohttp.ClientSession(connector=connector, timeout=build_timeout()) as session:
            for target in self.TARGETS:
                for keyword in self.KEYWORDS:
                    query = f"site:{target} {keyword}"
                    try:
                        urls = await self._duckduckgo_search(session, query)
                        for value in urls:
                            domain = extract_domain_from_url(value)
                            if not is_valid_domain(domain):
                                continue
                            if not (domain.endswith(".go.id") or domain.endswith(".ac.id")):
                                continue
                            self.candidates.add(domain)
                    except Exception as exc:
                        logger.warning("method_c query failed (%s): %s", query, exc)

                    await asyncio.sleep(1.0)

        await asyncio.sleep(0.250)

        duration = time.perf_counter() - start
        self._save_results(duration=duration)
        logger.info("method_c completed with %d domains", len(self.candidates))
        return self.candidates

    def _save_results(self, duration: float) -> None:
        payload = {
            "timestamp": utc_now(),
            "method": self.get_method_name(),
            "keyword_count": len(self.KEYWORDS),
            "candidate_count": len(self.candidates),
            "time_seconds": round(duration, 3),
            "domains": sorted(self.candidates),
        }

        with self.get_output_file().open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)


class MethodD(HuntingMethod):
    """OSINT and community source aggregation."""

    SOURCES = {
        "google_sheets": {
            "url": os.getenv("COMMUNITY_SHEET_CSV_URL", ""),
            "format": "csv",
        },
        "trustpositif": {
            "url": os.getenv("TRUSTPOSITIF_API_URL", "https://trustpositif.kominfo.go.id/"),
            "format": "json",
        },
        "adguard": {
            "url": "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/GamblingFilter/sections/adblock.txt",
            "format": "adblock",
        },
        "hagezi": {
            "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/gambling.txt",
            "format": "plaintext",
        },
    }

    def __init__(self, test_mode: bool = False) -> None:
        self.test_mode = test_mode
        self.candidates: Set[str] = set()

    def get_method_name(self) -> str:
        return "osint_community"

    def get_output_file(self) -> Path:
        return DATA_DIR / "candidates_d.json"

    def _parse_csv(self, content: str) -> Set[str]:
        out: Set[str] = set()
        reader = csv.reader(content.splitlines())
        rows = list(reader)
        if not rows:
            return out

        first_row = rows[0]
        start_index = 0
        if first_row:
            first_value = normalize_domain(first_row[0])
            # If first row is not a valid domain we treat it as header.
            if not is_valid_domain(first_value):
                start_index = 1

        for row in rows[start_index:]:
            if not row:
                continue
            domain = normalize_domain(row[0])
            if is_valid_domain(domain):
                out.add(domain)

        return out

    def _parse_json(self, content: str) -> Set[str]:
        out: Set[str] = set()
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return out

        items: Iterable[Any]
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            if isinstance(data.get("data"), list):
                items = data["data"]
            elif isinstance(data.get("results"), list):
                items = data["results"]
            else:
                items = []
        else:
            items = []

        for item in items:
            if isinstance(item, str):
                domain = normalize_domain(item)
            elif isinstance(item, dict):
                domain = normalize_domain(
                    item.get("domain")
                    or item.get("host")
                    or item.get("value")
                    or item.get("name")
                )
            else:
                domain = None

            if is_valid_domain(domain):
                out.add(domain)

        return out

    def _parse_adblock(self, content: str) -> Set[str]:
        out: Set[str] = set()
        for line in content.splitlines():
            row = line.strip()
            if not row or row.startswith("!") or row.startswith("#"):
                continue
            if not row.startswith("||"):
                continue
            domain = row.replace("||", "", 1).split("^")[0].strip()
            domain = normalize_domain(domain)
            if is_valid_domain(domain):
                out.add(domain)
        return out

    def _parse_plaintext(self, content: str) -> Set[str]:
        out: Set[str] = set()
        for line in content.splitlines():
            row = line.strip()
            if not row or row.startswith("#"):
                continue
            domain = parse_hosts_or_domain_line(row)
            if is_valid_domain(domain):
                out.add(domain)
        return out

    async def _parse_format(self, content: str, fmt: str) -> Set[str]:
        if fmt == "csv":
            return self._parse_csv(content)
        if fmt == "json":
            return self._parse_json(content)
        if fmt == "adblock":
            return self._parse_adblock(content)
        if fmt == "plaintext":
            return self._parse_plaintext(content)
        return set()

    async def hunt(self) -> Set[str]:
        logger.info("method_d started")

        if self.test_mode:
            self.candidates = {
                "laporanjudi123.com",
                "mirror-slotgacor.net",
                "togellinkbaru.xyz",
            }
            self._save_results(duration=0.0)
            return self.candidates

        start = time.perf_counter()
        connector = build_connector()

        async with aiohttp.ClientSession(connector=connector, timeout=build_timeout()) as session:
            for name, source in self.SOURCES.items():
                url = source.get("url", "")
                fmt = source.get("format", "")
                if not url:
                    logger.info("method_d source=%s skipped (missing url)", name)
                    continue

                try:
                    async with session.get(url, timeout=build_timeout()) as resp:
                        if resp.status != 200:
                            logger.warning("method_d source=%s status=%s", name, resp.status)
                            continue
                        content = await resp.text()

                    domains = await self._parse_format(content, fmt)
                    self.candidates.update(domains)
                    logger.info("method_d source=%s domains=%d", name, len(domains))
                except Exception as exc:
                    logger.warning("method_d source=%s failed: %s", name, exc)

                await asyncio.sleep(1.0)

        await asyncio.sleep(0.250)

        duration = time.perf_counter() - start
        self._save_results(duration=duration)
        logger.info("method_d completed with %d domains", len(self.candidates))
        return self.candidates

    def _save_results(self, duration: float) -> None:
        payload = {
            "timestamp": utc_now(),
            "method": self.get_method_name(),
            "source_count": len(self.SOURCES),
            "candidate_count": len(self.candidates),
            "time_seconds": round(duration, 3),
            "domains": sorted(self.candidates),
        }

        with self.get_output_file().open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)


class MethodE(HuntingMethod):
    """Curated gambling feed ingestion."""

    SOURCES = {
        "blocklistproject_gambling": {
            "url": "https://raw.githubusercontent.com/blocklistproject/Lists/master/gambling.txt",
            "format": "hosts",
        },
        "hagezi_gambling_hosts": {
            "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/gambling.txt",
            "format": "hosts",
        },
        "hagezi_gambling_domains": {
            "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/gambling.txt",
            "format": "plaintext",
        },
    }

    def __init__(self, test_mode: bool = False) -> None:
        self.test_mode = test_mode
        self.candidates: Set[str] = set()
        self.source_yield: Dict[str, int] = {}

    def get_method_name(self) -> str:
        return "curated_gambling_feeds"

    def get_output_file(self) -> Path:
        return DATA_DIR / "candidates_e.json"

    @staticmethod
    def _parse_content(content: str) -> Set[str]:
        out: Set[str] = set()
        for line in content.splitlines():
            domain = parse_hosts_or_domain_line(line)
            if is_valid_domain(domain):
                out.add(domain)
        return out

    async def hunt(self) -> Set[str]:
        logger.info("method_e started")

        if self.test_mode:
            self.candidates = {
                "slotkomunitasid.com",
                "betlokalbaru.net",
                "rtpindonesia777.site",
            }
            self.source_yield = {"fixture": len(self.candidates)}
            self._save_results(duration=0.0)
            return self.candidates

        start = time.perf_counter()
        connector = build_connector()

        async with aiohttp.ClientSession(connector=connector, timeout=build_timeout()) as session:
            for source_name, source in self.SOURCES.items():
                url = source.get("url", "")
                if not url:
                    continue

                try:
                    async with session.get(url, timeout=build_timeout()) as resp:
                        if resp.status != 200:
                            logger.warning("method_e source=%s status=%s", source_name, resp.status)
                            self.source_yield[source_name] = 0
                            continue
                        content = await resp.text()

                    domains = self._parse_content(content)
                    self.candidates.update(domains)
                    self.source_yield[source_name] = len(domains)
                    logger.info("method_e source=%s domains=%d", source_name, len(domains))
                except Exception as exc:
                    logger.warning("method_e source=%s failed: %s", source_name, exc)
                    self.source_yield[source_name] = 0

                await asyncio.sleep(0.8)

        await asyncio.sleep(0.250)

        duration = time.perf_counter() - start
        self._save_results(duration=duration)
        logger.info("method_e completed with %d domains", len(self.candidates))
        return self.candidates

    def _save_results(self, duration: float) -> None:
        payload = {
            "timestamp": utc_now(),
            "method": self.get_method_name(),
            "source_count": len(self.SOURCES),
            "source_yield": self.source_yield,
            "candidate_count": len(self.candidates),
            "time_seconds": round(duration, 3),
            "domains": sorted(self.candidates),
        }

        with self.get_output_file().open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)


class MethodF(HuntingMethod):
    """Platform abuse sweep for rapidly rehosted gambling mirrors."""

    PLATFORM_SUFFIXES: Sequence[str] = (
        "pages.dev",
        "vercel.app",
        "netlify.app",
        "workers.dev",
        "github.io",
        "godaddysites.com",
        "wixsite.com",
        "blogspot.com",
    )

    KEYWORDS: Sequence[str] = (
        "slot gacor",
        "situs judi",
        "rtp live",
        "togel online",
        "agen slot",
        "depo wd",
    )

    FEEDS = {
        "openphish_public": "https://raw.githubusercontent.com/openphish/public_feed/main/feed.txt",
    }

    def __init__(self, test_mode: bool = False) -> None:
        self.test_mode = test_mode
        self.candidates: Set[str] = set()
        self.query_count = 0

    def get_method_name(self) -> str:
        return "platform_abuse_sweep"

    def get_output_file(self) -> Path:
        return DATA_DIR / "candidates_f.json"

    async def _duckduckgo_search(self, session: aiohttp.ClientSession, query: str) -> List[str]:
        endpoint = "https://duckduckgo.com/html/"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"
        }

        async with session.get(
            endpoint,
            params={"q": query},
            headers=headers,
            timeout=build_timeout(),
        ) as resp:
            if resp.status != 200:
                return []
            html = await resp.text()

        soup = BeautifulSoup(html, "html.parser")
        hrefs: List[str] = []
        for tag in soup.select("a[href]"):
            href = tag.get("href", "")
            if not href or href.startswith("/"):
                continue
            hrefs.append(href)
        return hrefs

    def _extract_platform_domain(self, value: str) -> Optional[str]:
        domain = extract_domain_from_url(value)
        if not is_valid_domain(domain):
            return None
        if not is_platform_host(domain, self.PLATFORM_SUFFIXES):
            return None
        if not (looks_like_gambling_text(value) or looks_like_gambling_domain(domain)):
            return None
        return domain

    async def _sweep_search(self, session: aiohttp.ClientSession) -> None:
        for platform in self.PLATFORM_SUFFIXES:
            for keyword in self.KEYWORDS:
                query = f'site:{platform} "{keyword}"'
                self.query_count += 1
                try:
                    urls = await self._duckduckgo_search(session, query)
                    for value in urls:
                        candidate = self._extract_platform_domain(value)
                        if candidate:
                            self.candidates.add(candidate)
                except Exception as exc:
                    logger.warning("method_f query failed (%s): %s", query, exc)
                await asyncio.sleep(0.8)

    async def _sweep_feeds(self, session: aiohttp.ClientSession) -> None:
        for source_name, url in self.FEEDS.items():
            try:
                async with session.get(url, timeout=build_timeout()) as resp:
                    if resp.status != 200:
                        logger.warning("method_f feed=%s status=%s", source_name, resp.status)
                        continue
                    content = await resp.text()

                for row in content.splitlines():
                    value = row.strip()
                    if not value:
                        continue
                    candidate = self._extract_platform_domain(value)
                    if candidate:
                        self.candidates.add(candidate)
            except Exception as exc:
                logger.warning("method_f feed=%s failed: %s", source_name, exc)

            await asyncio.sleep(0.5)

    async def hunt(self) -> Set[str]:
        logger.info("method_f started")

        if self.test_mode:
            self.candidates = {
                "slotmirror-demo.pages.dev",
                "rtp-mirror-demo.vercel.app",
                "judol-clone-demo.netlify.app",
            }
            self.query_count = len(self.PLATFORM_SUFFIXES) * len(self.KEYWORDS)
            self._save_results(duration=0.0)
            return self.candidates

        start = time.perf_counter()
        connector = build_connector()

        async with aiohttp.ClientSession(connector=connector, timeout=build_timeout()) as session:
            await self._sweep_search(session)
            await self._sweep_feeds(session)

        await asyncio.sleep(0.250)

        duration = time.perf_counter() - start
        self._save_results(duration=duration)
        logger.info("method_f completed with %d domains", len(self.candidates))
        return self.candidates

    def _save_results(self, duration: float) -> None:
        payload = {
            "timestamp": utc_now(),
            "method": self.get_method_name(),
            "platform_count": len(self.PLATFORM_SUFFIXES),
            "query_count": self.query_count,
            "candidate_count": len(self.candidates),
            "time_seconds": round(duration, 3),
            "domains": sorted(self.candidates),
        }

        with self.get_output_file().open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)


class DomainHunter:
    """Main orchestrator for methods A-F and merged output."""

    def __init__(self, test_mode: bool = False) -> None:
        ensure_data_dir()
        self.test_mode = test_mode
        self.timestamp = utc_now()
        self.methods: Dict[str, HuntingMethod] = {
            "a": MethodA(test_mode=test_mode),
            "b": MethodB(test_mode=test_mode),
            "c": MethodC(test_mode=test_mode),
            "d": MethodD(test_mode=test_mode),
            "e": MethodE(test_mode=test_mode),
            "f": MethodF(test_mode=test_mode),
        }
        self.by_method: Dict[str, Dict[str, Any]] = {}
        self.domain_sources: Dict[str, Set[str]] = defaultdict(set)

    async def run_method(self, key: str) -> Set[str]:
        method = self.methods[key]
        domains = await method.hunt()
        method_name = method.get_method_name()
        for domain in domains:
            self.domain_sources[domain].add(method_name)

        self.by_method[method.get_method_name()] = {
            "count": len(domains),
            "file": method.get_output_file().relative_to(BASE_DIR).as_posix(),
            "timestamp": utc_now(),
        }
        return domains

    def build_domain_sources_map(self) -> Dict[str, List[str]]:
        file_to_method = {
            "candidates_a.json": "google_dorking",
            "candidates_b.json": "certificate_transparency",
            "candidates_c.json": "government_scanning",
            "candidates_d.json": "osint_community",
            "candidates_e.json": "curated_gambling_feeds",
            "candidates_f.json": "platform_abuse_sweep",
        }

        mapping: Dict[str, Set[str]] = defaultdict(set)
        for filename, method_name in file_to_method.items():
            path = DATA_DIR / filename
            if not path.exists():
                continue
            try:
                with path.open("r", encoding="utf-8") as fh:
                    data = json.load(fh)
                for raw in data.get("domains", []):
                    domain = normalize_domain(str(raw))
                    if is_valid_domain(domain):
                        mapping[domain].add(method_name)
            except Exception as exc:
                logger.warning("failed reading %s for domain_sources: %s", path.name, exc)

        for domain, methods in self.domain_sources.items():
            mapping[domain].update(methods)

        return {domain: sorted(methods) for domain, methods in sorted(mapping.items())}

    async def _run_methods_parallel(self, keys: List[str]) -> None:
        tasks = [self.run_method(key) for key in keys]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for key, result in zip(keys, results):
            if not isinstance(result, Exception):
                continue

            method = self.methods[key]
            method_name = method.get_method_name()
            logger.warning("%s failed during parallel execution: %s", method_name, result)
            self.by_method[method_name] = {
                "count": 0,
                "file": method.get_output_file().relative_to(BASE_DIR).as_posix(),
                "timestamp": utc_now(),
                "error": str(result),
            }

    async def run_all_hunts(self) -> Dict[str, Any]:
        parallel_enabled = os.getenv("HUNTER_PARALLEL_METHODS", "true").strip().lower() not in {
            "0",
            "false",
            "no",
        }

        if parallel_enabled:
            # Keep Selenium-heavy method A isolated, then run network-bound methods in parallel.
            await self.run_method("a")
            await self._run_methods_parallel(["b", "c", "d", "e", "f"])
        else:
            # Legacy fallback for environments preferring fully sequential traffic.
            for key in ["a", "b", "c", "d", "e", "f"]:
                await self.run_method(key)

        merged = self.consolidate_results()
        domain_sources = self.build_domain_sources_map()

        output = {
            "timestamp": self.timestamp,
            "candidate_count": len(merged),
            "by_method": self.by_method,
            "domain_sources": domain_sources,
            "domains": sorted(merged),
        }

        merged_file = DATA_DIR / "candidates_merged.json"
        with merged_file.open("w", encoding="utf-8") as fh:
            json.dump(output, fh, indent=2)

        logger.info("all methods complete, merged_count=%d", len(merged))
        return output

    def consolidate_results(self) -> Set[str]:
        merged: Set[str] = set()

        for filename in [
            "candidates_a.json",
            "candidates_b.json",
            "candidates_c.json",
            "candidates_d.json",
            "candidates_e.json",
            "candidates_f.json",
        ]:
            path = DATA_DIR / filename
            if not path.exists():
                logger.warning("missing %s during consolidation", path.name)
                continue

            try:
                with path.open("r", encoding="utf-8") as fh:
                    data = json.load(fh)
                for raw in data.get("domains", []):
                    domain = normalize_domain(raw)
                    if is_valid_domain(domain):
                        merged.add(domain)
            except Exception as exc:
                logger.warning("failed reading %s: %s", path.name, exc)

        return merged


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Anti-Judol domain hunter")
    parser.add_argument(
        "--method",
        choices=["all", "a", "b", "c", "d", "e", "f"],
        default="all",
        help="Run one method or all methods",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run with test fixtures (no external network dependency)",
    )
    return parser.parse_args()


async def _main_async(args: argparse.Namespace) -> int:
    hunter = DomainHunter(test_mode=args.test)

    if args.method == "all":
        await hunter.run_all_hunts()
        return 0

    await hunter.run_method(args.method)

    # Keep merged output updated even for single-method runs.
    merged = hunter.consolidate_results()
    domain_sources = hunter.build_domain_sources_map()
    merged_payload = {
        "timestamp": utc_now(),
        "candidate_count": len(merged),
        "by_method": hunter.by_method,
        "domain_sources": domain_sources,
        "domains": sorted(merged),
    }
    with (DATA_DIR / "candidates_merged.json").open("w", encoding="utf-8") as fh:
        json.dump(merged_payload, fh, indent=2)

    logger.info("single method complete, merged_count=%d", len(merged))
    return 0


def main() -> int:
    ensure_data_dir()
    args = parse_args()
    return asyncio.run(_main_async(args))


if __name__ == "__main__":
    raise SystemExit(main())
