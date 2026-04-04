#!/usr/bin/env python3
"""Consolidation engine for final blocklist artifacts and operational metadata."""

from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("consolidator")


def utc_now_dt() -> datetime:
    return datetime.now(timezone.utc)


def utc_now() -> str:
    return utc_now_dt().isoformat().replace("+00:00", "Z")


def parse_utc(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        return None


def normalize_domain(domain: str) -> str:
    d = (domain or "").strip().lower().rstrip(".")
    if d.startswith("www."):
        d = d[4:]
    return d


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        logger.warning("failed reading %s: %s", path, exc)
        return default


def to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def safe_relative(path: Path, base: Path) -> str:
    try:
        return path.resolve().relative_to(base.resolve()).as_posix()
    except Exception:
        return path.as_posix()


class BlocklistConsolidator:
    """Merge verification output, lifecycle state, quality metrics, and exports."""

    POSITIVE_STATUS = {"GAMBLING"}
    SUSPECT_STATUS = {"SUSPICIOUS", "BORDERLINE"}
    MIN_SOURCE_CALIBRATION_SAMPLES = 10

    def __init__(
        self,
        verification_file: Path,
        historical_file: Path,
        output_dir: Path,
        gambling_risk_threshold: float = 75.0,
        ttl_days: int = 7,
        stale_hours_threshold: float = 6.0,
        allowlist_file: Optional[Path] = None,
        appeals_file: Optional[Path] = None,
        candidates_file: Optional[Path] = None,
        source_calibration_profile_file: Optional[Path] = None,
        daily_changelog_file: Optional[Path] = None,
        kpi_monthly_file: Optional[Path] = None,
        pipeline_health_file: Optional[Path] = None,
        source_quality_file: Optional[Path] = None,
    ) -> None:
        self.verification_file = verification_file
        self.historical_file = historical_file
        self.output_dir = output_dir
        self.gambling_risk_threshold = self._normalize_gambling_threshold(gambling_risk_threshold)
        self.ttl_days = max(1, int(ttl_days))
        self.stale_hours_threshold = max(1.0, float(stale_hours_threshold))

        self.allowlist_file = allowlist_file or (DATA_DIR / "allowlist.json")
        self.appeals_file = appeals_file or (DATA_DIR / "domain_appeals.json")
        self.candidates_file = candidates_file or (DATA_DIR / "candidates_merged.json")
        self.source_calibration_profile_file = source_calibration_profile_file or (DATA_DIR / "source_calibration_profile.json")
        self.daily_changelog_file = daily_changelog_file or (DATA_DIR / "domain_changes_daily.json")
        self.kpi_monthly_file = kpi_monthly_file or (DATA_DIR / "kpi_monthly.json")
        self.pipeline_health_file = pipeline_health_file or (DATA_DIR / "pipeline_health.json")
        self.source_quality_file = source_quality_file or (DATA_DIR / "source_quality_metrics.json")

        self.output_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _normalize_gambling_threshold(value: Any, default: float = 0.75) -> float:
        try:
            parsed = float(value)
        except Exception:
            return default

        # Accept both ratio (0-1) and percentage (0-100) inputs.
        if parsed > 1.0:
            parsed = parsed / 100.0

        return max(0.20, min(0.98, parsed))

    def resolve_effective_gambling_threshold(self, verification_payload: Dict[str, Any]) -> float:
        effective = self.gambling_risk_threshold

        if not isinstance(verification_payload, dict):
            return effective

        config = verification_payload.get("config", {})
        if not isinstance(config, dict):
            return effective

        thresholds = config.get("thresholds", {})
        if not isinstance(thresholds, dict):
            return effective

        gambling_threshold = thresholds.get("gambling")
        if gambling_threshold is None:
            return effective

        return self._normalize_gambling_threshold(gambling_threshold, default=effective)

    def load_verification_payload(self) -> Dict[str, Any]:
        data = load_json(self.verification_file, {})
        if isinstance(data, dict):
            return data
        if isinstance(data, list):
            return {"domains": data, "timestamp": utc_now()}
        return {"domains": [], "timestamp": utc_now()}

    def load_historical_payload(self) -> Dict[str, Any]:
        data = load_json(self.historical_file, {})
        if isinstance(data, dict):
            return data
        return {}

    def load_candidates_payload(self) -> Dict[str, Any]:
        data = load_json(self.candidates_file, {})
        if isinstance(data, dict):
            return data
        return {}

    def load_allowlist(self) -> Tuple[Set[str], List[Dict[str, Any]]]:
        payload = load_json(self.allowlist_file, {})
        entries = payload.get("entries", []) if isinstance(payload, dict) else []

        active: Set[str] = set()
        normalized_entries: List[Dict[str, Any]] = []

        for row in entries:
            if not isinstance(row, dict):
                continue
            domain = normalize_domain(str(row.get("domain", "")))
            if not domain:
                continue
            row_active = bool(row.get("active", True))
            expires_at = parse_utc(str(row.get("expires_at", "")))
            if expires_at and expires_at < utc_now_dt():
                row_active = False

            normalized = {
                "domain": domain,
                "active": row_active,
                "approved_by": str(row.get("approved_by", "")).strip(),
                "ticket_id": str(row.get("ticket_id", "")).strip(),
                "reason": str(row.get("reason", "")).strip(),
                "approved_at": str(row.get("approved_at", "")).strip(),
                "review_due_at": str(row.get("review_due_at", "")).strip(),
                "expires_at": str(row.get("expires_at", "")).strip(),
            }
            normalized_entries.append(normalized)
            if row_active:
                active.add(domain)

        return active, normalized_entries

    def load_appeals(self) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Any]]:
        payload = load_json(self.appeals_file, {})
        entries = payload.get("entries", []) if isinstance(payload, dict) else []

        appeals: Dict[str, Dict[str, Any]] = {}
        total = accepted = open_count = rejected = 0

        for row in entries:
            if not isinstance(row, dict):
                continue
            domain = normalize_domain(str(row.get("domain", "")))
            if not domain:
                continue

            state = str(row.get("state", "open")).strip().lower()
            if state not in {"open", "accepted", "rejected", "closed"}:
                state = "open"

            appeals[domain] = {
                "state": state,
                "opened_at": str(row.get("opened_at", "")).strip(),
                "resolved_at": str(row.get("resolved_at", "")).strip(),
                "reviewed_by": str(row.get("reviewed_by", "")).strip(),
                "notes": str(row.get("notes", "")).strip(),
                "issue_id": str(row.get("issue_id", "")).strip(),
            }

            total += 1
            if state == "accepted":
                accepted += 1
            elif state == "open":
                open_count += 1
            elif state == "rejected":
                rejected += 1

        stats = {
            "total": total,
            "accepted": accepted,
            "open": open_count,
            "rejected": rejected,
            "closed": max(0, total - open_count),
        }
        return appeals, stats

    @staticmethod
    def historical_registry(payload: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        registry: Dict[str, Dict[str, Any]] = {}

        if isinstance(payload.get("domain_registry"), list):
            for row in payload.get("domain_registry", []):
                if not isinstance(row, dict):
                    continue
                domain = normalize_domain(str(row.get("domain", "")))
                if not domain:
                    continue
                registry[domain] = dict(row)
            return registry

        for domain in payload.get("blocklist", []):
            normalized = normalize_domain(str(domain))
            if not normalized:
                continue
            registry[normalized] = {
                "domain": normalized,
                "lifecycle_status": "active",
                "first_seen": payload.get("created_at", utc_now()),
                "last_seen": payload.get("created_at", utc_now()),
                "source_methods": ["legacy"],
                "last_verified_status": "GAMBLING",
                "confidence": 100.0,
                "risk_score": 1.0,
                "stale_days": 0,
                "ttl_expires_at": payload.get("created_at", utc_now()),
                "appeal_state": "none",
                "allowlisted": False,
                "evidence": {},
            }

        return registry

    @staticmethod
    def extract_evidence(item: Dict[str, Any]) -> Dict[str, Any]:
        analysis = item.get("analysis", {}) if isinstance(item, dict) else {}
        crawl = item.get("crawl", {}) if isinstance(item, dict) else {}
        ocr = analysis.get("ocr_second_pass", {}) if isinstance(analysis, dict) else {}

        danger_hits = analysis.get("danger_hits", {}) if isinstance(analysis, dict) else {}
        top_danger = sorted(danger_hits.items(), key=lambda x: x[1], reverse=True)[:5]

        return {
            "top_danger_signals": [name for name, _ in top_danger],
            "payment_hits": int(analysis.get("payment_hits", 0) or 0),
            "messaging_hits": int(analysis.get("messaging_hits", 0) or 0),
            "final_url": str(crawl.get("final_url", "") or ""),
            "crawl_ok": bool(crawl.get("ok", False)),
            "ocr_verdict": (ocr.get("scores") or {}).get("ocr_verdict") if isinstance(ocr, dict) else None,
            "ocr_applied": bool(ocr.get("applied", False)) if isinstance(ocr, dict) else False,
        }

    def lifecycle_status_for_domain(
        self,
        verified_item: Optional[Dict[str, Any]],
        existing: Dict[str, Any],
        allowlisted: bool,
        appeal_state: str,
        now_dt: datetime,
        effective_gambling_threshold: float,
    ) -> Tuple[str, int, str]:
        old_status = str(existing.get("lifecycle_status", "expired")).lower()
        last_seen_raw = str(existing.get("last_seen") or existing.get("first_seen") or "")

        if verified_item is not None:
            status = str(verified_item.get("status", "UNKNOWN")).upper()
            risk_score = to_float(verified_item.get("risk_score", 0.0), 0.0)

            if allowlisted or appeal_state in {"open", "accepted"}:
                lifecycle = "appealed"
            elif status in self.POSITIVE_STATUS and risk_score >= effective_gambling_threshold:
                lifecycle = "active"
            elif status in self.POSITIVE_STATUS:
                lifecycle = "suspect"
            elif status in self.SUSPECT_STATUS:
                lifecycle = "suspect"
            else:
                lifecycle = "suspect" if old_status in {"active", "suspect"} else "expired"

            expires_dt = now_dt + timedelta(days=self.ttl_days)
            return lifecycle, 0, expires_dt.isoformat().replace("+00:00", "Z")

        last_seen_dt = parse_utc(last_seen_raw)
        if not last_seen_dt:
            if allowlisted or appeal_state in {"open", "accepted"}:
                return "appealed", 9999, now_dt.isoformat().replace("+00:00", "Z")
            return "expired", 9999, now_dt.isoformat().replace("+00:00", "Z")

        stale_days = max(0, int((now_dt - last_seen_dt).total_seconds() // 86400))
        expires_dt = last_seen_dt + timedelta(days=self.ttl_days)

        if allowlisted or appeal_state in {"open", "accepted"}:
            lifecycle = "appealed"
        elif stale_days >= self.ttl_days:
            lifecycle = "expired"
        elif old_status in {"active", "suspect"}:
            lifecycle = old_status
        elif old_status == "appealed":
            lifecycle = "appealed"
        else:
            lifecycle = "expired"

        return lifecycle, stale_days, expires_dt.isoformat().replace("+00:00", "Z")

    def compute_source_metrics(
        self,
        domain_sources: Dict[str, List[str]],
        by_method: Dict[str, Dict[str, Any]],
        verified_map: Dict[str, Dict[str, Any]],
        registry: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Dict[str, Any]]:
        sources: Set[str] = set(by_method.keys())
        for methods in domain_sources.values():
            sources.update(methods)

        metrics: Dict[str, Dict[str, Any]] = {}
        for source in sorted(sources):
            source_domains = {d for d, methods in domain_sources.items() if source in methods}
            verified_domains = [verified_map[d] for d in source_domains if d in verified_map]

            verified_count = len(verified_domains)
            gambling_count = sum(1 for item in verified_domains if str(item.get("status", "")).upper() == "GAMBLING")
            active_count = sum(
                1
                for d in source_domains
                if str((registry.get(d) or {}).get("lifecycle_status", "")).lower() == "active"
            )

            candidate_total = int((by_method.get(source) or {}).get("count", 0))
            if candidate_total <= 0:
                candidate_total = len(source_domains)
            precision = (gambling_count / verified_count) if verified_count else 0.0
            source_yield = (active_count / candidate_total) if candidate_total else 0.0
            coverage_ratio = (verified_count / candidate_total) if candidate_total else 0.0

            metrics[source] = {
                "candidate_total": candidate_total,
                "verified_count": verified_count,
                "gambling_count": gambling_count,
                "active_count": active_count,
                "precision": round(precision, 4),
                "source_yield": round(source_yield, 4),
                "coverage_ratio": round(coverage_ratio, 4),
            }

        return metrics

    def build_source_calibration_profile(self, source_metrics: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        existing = load_json(self.source_calibration_profile_file, {})
        existing_sources = existing.get("sources", {}) if isinstance(existing, dict) else {}
        minimum_samples = int(existing.get("min_verified_samples", self.MIN_SOURCE_CALIBRATION_SAMPLES)) if isinstance(existing, dict) else self.MIN_SOURCE_CALIBRATION_SAMPLES
        minimum_samples = max(1, minimum_samples)

        profile_sources: Dict[str, Any] = {}
        for source, row in source_metrics.items():
            prev = existing_sources.get(source, {}) if isinstance(existing_sources, dict) else {}
            precision = to_float(row.get("precision", 0.0), 0.0)
            verified_count = int(row.get("verified_count", 0))

            if verified_count < minimum_samples:
                recommended = 1.0
                calibration_mode = "insufficient_data"
            else:
                # Center around neutral=1.0 and adapt when precision has enough evidence.
                recommended = max(0.85, min(1.15, 1.0 + ((precision - 0.50) * 0.40)))
                calibration_mode = "adaptive"

            locked = bool(prev.get("locked", False)) if isinstance(prev, dict) else False
            score_multiplier = to_float(prev.get("score_multiplier", recommended), recommended) if locked else recommended

            profile_sources[source] = {
                "score_multiplier": round(score_multiplier, 4),
                "recommended_multiplier": round(recommended, 4),
                "precision": round(precision, 4),
                "verified_count": verified_count,
                "locked": locked,
                "calibration_mode": calibration_mode,
                "updated_at": utc_now(),
            }

        profile = {
            "updated_at": utc_now(),
            "version": "1.0",
            "min_verified_samples": minimum_samples,
            "sources": profile_sources,
        }

        self.source_calibration_profile_file.write_text(json.dumps(profile, indent=2), encoding="utf-8")
        return profile

    def update_monthly_kpi(
        self,
        discovery_to_publish_latency_hours: Optional[float],
        dispute_rate: float,
        source_metrics: Dict[str, Dict[str, Any]],
        active_count: int,
    ) -> Dict[str, Any]:
        payload = load_json(self.kpi_monthly_file, {"records": {}})
        if not isinstance(payload, dict):
            payload = {"records": {}}
        if not isinstance(payload.get("records"), dict):
            payload["records"] = {}

        month_key = utc_now()[:7]
        source_yields = [to_float(x.get("source_yield", 0.0), 0.0) for x in source_metrics.values() if isinstance(x, dict)]
        avg_source_yield = (sum(source_yields) / len(source_yields)) if source_yields else 0.0

        payload["records"][month_key] = {
            "month": month_key,
            "updated_at": utc_now(),
            "discovery_to_publish_latency_hours": None
            if discovery_to_publish_latency_hours is None
            else round(discovery_to_publish_latency_hours, 3),
            "dispute_rate": round(dispute_rate, 4),
            "average_source_yield": round(avg_source_yield, 4),
            "active_domains": active_count,
        }

        self.kpi_monthly_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return payload

    def update_daily_changes(self, event: Dict[str, Any]) -> Dict[str, Any]:
        payload = load_json(self.daily_changelog_file, {"events": []})
        if not isinstance(payload, dict):
            payload = {"events": []}
        if not isinstance(payload.get("events"), list):
            payload["events"] = []

        payload["events"].append(event)
        payload["events"] = payload["events"][-365:]
        payload["updated_at"] = utc_now()

        self.daily_changelog_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return payload

    def append_changelog(self, added: List[str], removed: List[str], downgraded: List[str], total_active: int) -> Path:
        target = self.output_dir / "CHANGELOG.md"

        lines = [
            f"## {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"- Active domains: {total_active}",
            f"- Added: {len(added)}",
            f"- Removed: {len(removed)}",
            f"- Downgraded: {len(downgraded)}",
        ]

        if added:
            lines.append("- Added samples:")
            for item in added[:20]:
                lines.append(f"  - {item}")

        if removed:
            lines.append("- Removed samples:")
            for item in removed[:20]:
                lines.append(f"  - {item}")

        if downgraded:
            lines.append("- Downgraded samples:")
            for item in downgraded[:20]:
                lines.append(f"  - {item}")

        lines.append("")

        with target.open("a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")

        return target

    def export_txt(self, domains: Sequence[str]) -> Path:
        target = self.output_dir / "blocklist.txt"
        lines = [
            "# Anti-Judol Gambling Blocklist",
            f"# Generated: {utc_now()}",
            f"# Active domains: {len(domains)}",
            "",
        ]
        lines.extend(sorted(domains))
        target.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return target

    def export_dnsmasq(self, domains: Sequence[str]) -> Path:
        target = self.output_dir / "blocklist-dnsmasq.conf"
        lines = [
            "# Anti-Judol dnsmasq format",
            f"# Generated: {utc_now()}",
            "",
        ]
        for domain in sorted(domains):
            lines.append(f"address=/{domain}/0.0.0.0")
            lines.append(f"address=/{domain}/::")
        target.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return target

    def export_hosts(self, domains: Sequence[str]) -> Path:
        target = self.output_dir / "blocklist-hosts.txt"
        lines = [
            "# Anti-Judol hosts format",
            f"# Generated: {utc_now()}",
            "",
        ]
        for domain in sorted(domains):
            lines.append(f"0.0.0.0 {domain}")
            lines.append(f":: {domain}")
        target.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return target

    def run(self) -> Dict[str, Any]:
        logger.info("consolidator started")

        now_dt = utc_now_dt()

        verification_payload = self.load_verification_payload()
        effective_gambling_threshold = self.resolve_effective_gambling_threshold(verification_payload)
        verified_list_raw = verification_payload.get("domains", []) if isinstance(verification_payload, dict) else []
        verified_list = [x for x in verified_list_raw if isinstance(x, dict)]

        historical_payload = self.load_historical_payload()
        registry_previous = self.historical_registry(historical_payload)
        previous_active = {
            d
            for d, row in registry_previous.items()
            if str((row or {}).get("lifecycle_status", "")).lower() == "active"
        }

        candidates_payload = self.load_candidates_payload()
        domain_sources = candidates_payload.get("domain_sources", {}) if isinstance(candidates_payload, dict) else {}
        by_method = candidates_payload.get("by_method", {}) if isinstance(candidates_payload, dict) else {}
        if not isinstance(domain_sources, dict):
            domain_sources = {}
        if not isinstance(by_method, dict):
            by_method = {}

        allowlist_domains, allowlist_entries = self.load_allowlist()
        appeals_map, dispute_stats = self.load_appeals()

        verified_map: Dict[str, Dict[str, Any]] = {}
        status_counts = {"GAMBLING": 0, "SUSPICIOUS": 0, "BORDERLINE": 0, "SAFE": 0, "UNKNOWN": 0}
        confidence_values: List[float] = []
        gambling_confidence_values: List[float] = []

        for row in verified_list:
            domain = normalize_domain(str(row.get("domain", "")))
            if not domain:
                continue

            status = str(row.get("status", "UNKNOWN")).upper()
            if status not in status_counts:
                status = "UNKNOWN"
            status_counts[status] += 1

            confidence = to_float(row.get("confidence", 0.0), 0.0)
            confidence_values.append(confidence)
            if status == "GAMBLING":
                gambling_confidence_values.append(confidence)

            row_copy = dict(row)
            row_copy["domain"] = domain
            verified_map[domain] = row_copy

            if domain not in domain_sources:
                source_methods = row_copy.get("source_methods", [])
                if isinstance(source_methods, list) and source_methods:
                    domain_sources[domain] = sorted({str(x).strip() for x in source_methods if str(x).strip()})

        unattributed_verified_domains: List[str] = []
        for domain in sorted(verified_map.keys()):
            methods = domain_sources.get(domain)
            if isinstance(methods, list):
                normalized_methods = sorted({str(x).strip() for x in methods if str(x).strip()})
            else:
                normalized_methods = []

            if normalized_methods:
                domain_sources[domain] = normalized_methods
                continue

            domain_sources[domain] = ["unattributed"]
            unattributed_verified_domains.append(domain)

        all_domains = set(registry_previous.keys()) | set(verified_map.keys()) | set(domain_sources.keys()) | allowlist_domains | set(appeals_map.keys())

        registry_new: Dict[str, Dict[str, Any]] = {}
        active_domains: Set[str] = set()

        added: List[str] = []
        removed: List[str] = []
        downgraded: List[str] = []

        for domain in sorted(all_domains):
            existing = dict(registry_previous.get(domain, {}))
            verified_item = verified_map.get(domain)
            allowlisted = domain in allowlist_domains
            appeal_state = str((appeals_map.get(domain) or {}).get("state", "none")).lower()
            if appeal_state not in {"open", "accepted", "rejected", "closed"}:
                appeal_state = "none"

            lifecycle_status, stale_days, ttl_expires_at = self.lifecycle_status_for_domain(
                verified_item=verified_item,
                existing=existing,
                allowlisted=allowlisted,
                appeal_state=appeal_state,
                now_dt=now_dt,
                effective_gambling_threshold=effective_gambling_threshold,
            )

            old_status = str(existing.get("lifecycle_status", "expired")).lower()

            source_methods_existing = existing.get("source_methods", [])
            if not isinstance(source_methods_existing, list):
                source_methods_existing = []
            source_methods_current = domain_sources.get(domain, [])
            if not isinstance(source_methods_current, list):
                source_methods_current = []
            source_methods = sorted(
                {
                    str(x).strip()
                    for x in list(source_methods_existing) + list(source_methods_current)
                    if str(x).strip()
                }
            )

            first_seen = str(existing.get("first_seen", "") or "").strip() or utc_now()
            if verified_item is not None:
                last_seen = utc_now()
                last_verified_status = str(verified_item.get("status", "UNKNOWN")).upper()
                confidence = round(to_float(verified_item.get("confidence", 0.0), 0.0), 3)
                risk_score = round(to_float(verified_item.get("risk_score", 0.0), 0.0), 6)
                evidence = self.extract_evidence(verified_item)
            else:
                last_seen = str(existing.get("last_seen", "") or first_seen)
                last_verified_status = str(existing.get("last_verified_status", "UNKNOWN")).upper()
                confidence = round(to_float(existing.get("confidence", 0.0), 0.0), 3)
                risk_score = round(to_float(existing.get("risk_score", 0.0), 0.0), 6)
                evidence = existing.get("evidence", {}) if isinstance(existing.get("evidence", {}), dict) else {}

            entry = {
                "domain": domain,
                "lifecycle_status": lifecycle_status,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "source_methods": source_methods,
                "last_verified_status": last_verified_status,
                "confidence": confidence,
                "risk_score": risk_score,
                "stale_days": stale_days,
                "ttl_expires_at": ttl_expires_at,
                "appeal_state": appeal_state,
                "allowlisted": allowlisted,
                "evidence": evidence,
            }
            registry_new[domain] = entry

            if lifecycle_status == "active":
                active_domains.add(domain)

            if old_status != lifecycle_status:
                if lifecycle_status == "active" and old_status != "active":
                    added.append(domain)
                if old_status == "active" and lifecycle_status != "active":
                    removed.append(domain)
                    downgraded.append(domain)

        lifecycle_counts = {"active": 0, "suspect": 0, "expired": 0, "appealed": 0}
        for row in registry_new.values():
            lifecycle = str(row.get("lifecycle_status", "expired")).lower()
            if lifecycle in lifecycle_counts:
                lifecycle_counts[lifecycle] += 1

        source_metrics = self.compute_source_metrics(
            domain_sources={d: v for d, v in domain_sources.items() if isinstance(v, list)},
            by_method={k: v for k, v in by_method.items() if isinstance(v, dict)},
            verified_map=verified_map,
            registry=registry_new,
        )

        covered_verified_domains = {
            d
            for d, methods in domain_sources.items()
            if d in verified_map and isinstance(methods, list) and len(methods) > 0
        }
        source_mapping_coverage_ratio = len(covered_verified_domains) / max(1, len(verified_map))
        source_verified_total = sum(int((row or {}).get("verified_count", 0)) for row in source_metrics.values())

        telemetry_warnings: List[str] = []
        if len(verified_map) > 0 and source_mapping_coverage_ratio < 0.95:
            telemetry_warnings.append("source_mapping_coverage_low")
        if len(verified_map) > 0 and source_verified_total <= 0:
            telemetry_warnings.append("source_metrics_no_verified_domains")
        if dispute_stats.get("total", 0) <= 0:
            telemetry_warnings.append("appeals_registry_empty")

        source_quality_payload = {
            "updated_at": utc_now(),
            "sources": source_metrics,
            "telemetry": {
                "verified_domains_total": len(verified_map),
                "covered_verified_domains": len(covered_verified_domains),
                "source_mapping_coverage_ratio": round(source_mapping_coverage_ratio, 4),
                "unattributed_verified_domains": unattributed_verified_domains[:200],
                "warnings": telemetry_warnings,
            },
        }

        source_profile = self.build_source_calibration_profile(source_metrics)
        self.source_quality_file.write_text(json.dumps(source_quality_payload, indent=2), encoding="utf-8")

        hunt_ts = parse_utc(str(candidates_payload.get("timestamp", "")))
        verify_ts = parse_utc(str(verification_payload.get("timestamp", "")))
        publish_ts = now_dt

        hunt_age_hours = None if hunt_ts is None else round((publish_ts - hunt_ts).total_seconds() / 3600.0, 3)
        verify_age_hours = None if verify_ts is None else round((publish_ts - verify_ts).total_seconds() / 3600.0, 3)

        freshness = {
            "hunt_last_success_at": hunt_ts.isoformat().replace("+00:00", "Z") if hunt_ts else None,
            "verify_last_success_at": verify_ts.isoformat().replace("+00:00", "Z") if verify_ts else None,
            "publish_last_success_at": publish_ts.isoformat().replace("+00:00", "Z"),
            "hunt_age_hours": hunt_age_hours,
            "verify_age_hours": verify_age_hours,
            "publish_age_hours": 0.0,
        }

        is_stale = False
        stale_reasons: List[str] = []
        if hunt_age_hours is None or hunt_age_hours > self.stale_hours_threshold:
            is_stale = True
            stale_reasons.append("hunt_data_stale")
        if verify_age_hours is None or verify_age_hours > self.stale_hours_threshold:
            is_stale = True
            stale_reasons.append("verify_data_stale")

        health_payload = {
            "generated_at": utc_now(),
            "stale_hours_threshold": self.stale_hours_threshold,
            "status": "stale" if is_stale else "healthy",
            "stale": is_stale,
            "reasons": stale_reasons,
            "freshness": freshness,
            "governance": {
                "appeals_registry_state": "active" if dispute_stats.get("total", 0) > 0 else "empty",
                "appeals_total": int(dispute_stats.get("total", 0) or 0),
                "appeals_open": int(dispute_stats.get("open", 0) or 0),
            },
        }
        self.pipeline_health_file.write_text(json.dumps(health_payload, indent=2), encoding="utf-8")

        dispute_rate = (dispute_stats["total"] / max(1, len(active_domains)))
        confirmed_dispute_rate = (dispute_stats["accepted"] / max(1, len(active_domains)))

        discovery_latency_hours = None
        if hunt_ts is not None:
            discovery_latency_hours = (publish_ts - hunt_ts).total_seconds() / 3600.0

        monthly_kpi_payload = self.update_monthly_kpi(
            discovery_to_publish_latency_hours=discovery_latency_hours,
            dispute_rate=dispute_rate,
            source_metrics=source_metrics,
            active_count=len(active_domains),
        )

        daily_event = {
            "timestamp": utc_now(),
            "date": utc_now()[:10],
            "added": sorted(added),
            "removed": sorted(removed),
            "downgraded": sorted(downgraded),
            "counts": {
                "added": len(added),
                "removed": len(removed),
                "downgraded": len(downgraded),
            },
        }
        daily_changes_payload = self.update_daily_changes(daily_event)

        average_confidence = (sum(confidence_values) / len(confidence_values)) if confidence_values else 0.0
        gambling_average_confidence = (
            sum(gambling_confidence_values) / len(gambling_confidence_values)
            if gambling_confidence_values
            else 0.0
        )

        blocklist_payload = {
            "schema_version": "3.0",
            "created_at": utc_now(),
            "metadata": {
                "name": "Anti-Judol Indonesia Gambling Blocklist",
                "description": "Automated and AI-verified gambling domain blocklist",
                "project": "hanzantijudol",
                "update_frequency": "3 hours",
                "license": "MIT",
            },
            "statistics": {
                "total_domains": len(active_domains),
                "historical_domains": len(previous_active),
                "new_domains_this_cycle": len(added),
                "removed_domains_this_cycle": len(removed),
                "downgraded_domains_this_cycle": len(downgraded),
                "average_confidence": round(average_confidence, 2),
                "gambling_average_confidence": round(gambling_average_confidence, 2),
                "status_counts_from_verifier": status_counts,
                "lifecycle_counts": lifecycle_counts,
            },
            "quality_metrics": {
                "precision_by_source": {
                    source: row["precision"]
                    for source, row in source_metrics.items()
                },
                "coverage_by_source": {
                    source: row.get("coverage_ratio", 0.0)
                    for source, row in source_metrics.items()
                },
                "dispute_rate": round(dispute_rate, 4),
                "confirmed_false_positive_rate": round(confirmed_dispute_rate, 4),
                "effective_gambling_risk_threshold": round(effective_gambling_threshold, 4),
                "source_mapping_coverage_ratio": round(source_mapping_coverage_ratio, 4),
                "unattributed_verified_domains": unattributed_verified_domains[:200],
                "telemetry_warnings": telemetry_warnings,
                "source_yield": {
                    source: row["source_yield"]
                    for source, row in source_metrics.items()
                },
            },
            "freshness": freshness,
            "policy": {
                "allowlist": {
                    "active_domains": sorted(allowlist_domains),
                    "entry_count": len(allowlist_entries),
                    "file": safe_relative(self.allowlist_file, BASE_DIR),
                },
                "appeals": {
                    **dispute_stats,
                    "file": safe_relative(self.appeals_file, BASE_DIR),
                },
            },
            "kpi_monthly": monthly_kpi_payload.get("records", {}),
            "source_metrics": source_metrics,
            "source_calibration": source_profile,
            "daily_changes": daily_changes_payload,
            "pipeline_health": health_payload,
            "blocklist": sorted(active_domains),
            "domain_registry": [registry_new[key] for key in sorted(registry_new.keys())],
        }

        blocklist_path = self.output_dir / "blocklist.json"
        blocklist_path.write_text(json.dumps(blocklist_payload, indent=2), encoding="utf-8")

        statistics_payload = {
            "generated_at": utc_now(),
            "totals": {
                "active_domains": len(active_domains),
                "new_domains": len(added),
                "removed_domains": len(removed),
                "downgraded_domains": len(downgraded),
            },
            "verification": {
                "status_counts": status_counts,
                "lifecycle_counts": lifecycle_counts,
                "average_confidence": round(average_confidence, 2),
                "gambling_average_confidence": round(gambling_average_confidence, 2),
            },
            "quality": {
                "precision_by_source": {
                    source: row["precision"]
                    for source, row in source_metrics.items()
                },
                "coverage_by_source": {
                    source: row.get("coverage_ratio", 0.0)
                    for source, row in source_metrics.items()
                },
                "dispute_rate": round(dispute_rate, 4),
                "confirmed_false_positive_rate": round(confirmed_dispute_rate, 4),
                "effective_gambling_risk_threshold": round(effective_gambling_threshold, 4),
                "source_mapping_coverage_ratio": round(source_mapping_coverage_ratio, 4),
                "unattributed_verified_domains": unattributed_verified_domains[:200],
                "telemetry_warnings": telemetry_warnings,
                "source_yield": {
                    source: row["source_yield"]
                    for source, row in source_metrics.items()
                },
            },
            "freshness": freshness,
            "pipeline_health": health_payload,
        }

        statistics_path = self.output_dir / "statistics.json"
        statistics_path.write_text(json.dumps(statistics_payload, indent=2), encoding="utf-8")

        txt_path = self.export_txt(sorted(active_domains))
        dnsmasq_path = self.export_dnsmasq(sorted(active_domains))
        hosts_path = self.export_hosts(sorted(active_domains))
        changelog_path = self.append_changelog(added, removed, downgraded, len(active_domains))

        summary = {
            "timestamp": utc_now(),
            "verified_count": len(verified_map),
            "active_count": len(active_domains),
            "lifecycle_counts": lifecycle_counts,
            "new_domains": len(added),
            "removed_domains": len(removed),
            "downgraded_domains": len(downgraded),
            "artifacts": {
                "json": str(blocklist_path),
                "txt": str(txt_path),
                "dnsmasq": str(dnsmasq_path),
                "hosts": str(hosts_path),
                "statistics": str(statistics_path),
                "changelog": str(changelog_path),
                "daily_changes": str(self.daily_changelog_file),
                "source_quality": str(self.source_quality_file),
                "source_calibration": str(self.source_calibration_profile_file),
                "kpi_monthly": str(self.kpi_monthly_file),
                "pipeline_health": str(self.pipeline_health_file),
            },
        }

        logger.info(
            "consolidator finished | verified=%d active=%d new=%d removed=%d",
            len(verified_map),
            len(active_domains),
            len(added),
            len(removed),
        )
        return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate final blocklist artifacts")
    parser.add_argument(
        "--verified",
        default=str(DATA_DIR / "verified_domains.json"),
        help="Path to verified domains input",
    )
    parser.add_argument(
        "--historical",
        default=str(DATA_DIR / "blocklist.json"),
        help="Path to existing blocklist.json",
    )
    parser.add_argument(
        "--output-dir",
        default=str(DATA_DIR),
        help="Directory for generated artifacts",
    )
    parser.add_argument(
        "--gambling-risk-threshold",
        dest="gambling_risk_threshold",
        type=float,
        default=75.0,
        help="Minimum GAMBLING risk threshold (ratio 0-1 or percentage 0-100) for active lifecycle",
    )
    parser.add_argument(
        "--confidence-threshold",
        dest="gambling_risk_threshold",
        type=float,
        default=75.0,
        help="Deprecated alias of --gambling-risk-threshold",
    )
    parser.add_argument(
        "--ttl-days",
        type=int,
        default=7,
        help="Days before unseen active/suspect domains are marked expired",
    )
    parser.add_argument(
        "--stale-hours-threshold",
        type=float,
        default=6.0,
        help="Freshness threshold (hours) for stale data health alert",
    )
    parser.add_argument(
        "--allowlist-file",
        default=str(DATA_DIR / "allowlist.json"),
        help="Allowlist policy data file",
    )
    parser.add_argument(
        "--appeals-file",
        default=str(DATA_DIR / "domain_appeals.json"),
        help="Domain appeals/disputes data file",
    )
    parser.add_argument(
        "--candidates-file",
        default=str(DATA_DIR / "candidates_merged.json"),
        help="Merged candidates file with by_method and domain_sources",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    consolidator = BlocklistConsolidator(
        verification_file=Path(args.verified),
        historical_file=Path(args.historical),
        output_dir=Path(args.output_dir),
        gambling_risk_threshold=args.gambling_risk_threshold,
        ttl_days=args.ttl_days,
        stale_hours_threshold=args.stale_hours_threshold,
        allowlist_file=Path(args.allowlist_file),
        appeals_file=Path(args.appeals_file),
        candidates_file=Path(args.candidates_file),
    )
    summary = consolidator.run()
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
