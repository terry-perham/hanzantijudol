#!/usr/bin/env python3
"""Build static GitHub Pages artifact with operational dashboard payload."""

from __future__ import annotations

import argparse
import json
import os
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


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


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return default


def copy_required_files(data_dir: Path, site_dir: Path) -> Dict[str, str]:
    required_mapping: Tuple[Tuple[str, str], ...] = (
        ("blocklist.json", "api/v1/blocklist.json"),
        ("statistics.json", "api/v1/statistics.json"),
        ("blocklist.txt", "blocklist.txt"),
        ("blocklist-dnsmasq.conf", "blocklist-dnsmasq.conf"),
        ("blocklist-hosts.txt", "blocklist-hosts.txt"),
        ("CHANGELOG.md", "CHANGELOG.md"),
    )

    optional_mapping: Tuple[Tuple[str, str], ...] = (
        ("source_quality_metrics.json", "api/v1/source_quality_metrics.json"),
        ("domain_changes_daily.json", "api/v1/domain_changes_daily.json"),
        ("pipeline_health.json", "api/v1/pipeline_health.json"),
        ("source_calibration_profile.json", "api/v1/source_calibration_profile.json"),
        ("kpi_monthly.json", "api/v1/kpi_monthly.json"),
        ("allowlist.json", "api/v1/allowlist.json"),
        ("domain_appeals.json", "api/v1/domain_appeals.json"),
        ("verified_domains.json", "api/v1/verified_domains.json"),
        ("candidates_merged.json", "api/v1/candidates_merged.json"),
    )

    copied: Dict[str, str] = {}

    for src_name, dst_rel in required_mapping:
        src = data_dir / src_name
        if not src.exists():
            raise FileNotFoundError(f"Missing required artifact: {src}")

        dst = site_dir / dst_rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        copied[src_name] = dst.relative_to(site_dir).as_posix()

    for src_name, dst_rel in optional_mapping:
        src = data_dir / src_name
        if not src.exists():
            continue

        dst = site_dir / dst_rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        copied[src_name] = dst.relative_to(site_dir).as_posix()

    return copied


def normalize_registry_entries(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []

    for row in entries:
        if not isinstance(row, dict):
            continue

        domain = str(row.get("domain", "")).strip().lower()
        if not domain:
            continue

        source_methods = row.get("source_methods", [])
        if not isinstance(source_methods, list):
            source_methods = []

        evidence = row.get("evidence", {}) if isinstance(row.get("evidence", {}), dict) else {}
        danger = evidence.get("top_danger_signals", []) if isinstance(evidence.get("top_danger_signals", []), list) else []

        normalized.append(
            {
                "domain": domain,
                "lifecycle_status": str(row.get("lifecycle_status", "expired")).lower(),
                "confidence": float(row.get("confidence", 0.0) or 0.0),
                "risk_score": float(row.get("risk_score", 0.0) or 0.0),
                "last_verified_status": str(row.get("last_verified_status", "UNKNOWN")).upper(),
                "first_seen": str(row.get("first_seen", "") or ""),
                "last_seen": str(row.get("last_seen", "") or ""),
                "ttl_expires_at": str(row.get("ttl_expires_at", "") or ""),
                "stale_days": int(row.get("stale_days", 0) or 0),
                "allowlisted": bool(row.get("allowlisted", False)),
                "appeal_state": str(row.get("appeal_state", "none") or "none"),
                "source_methods": sorted({str(x).strip() for x in source_methods if str(x).strip()}),
                "evidence": {
                    "top_danger_signals": [str(x) for x in danger[:6]],
                    "payment_hits": int(evidence.get("payment_hits", 0) or 0),
                    "messaging_hits": int(evidence.get("messaging_hits", 0) or 0),
                    "crawl_ok": bool(evidence.get("crawl_ok", False)),
                    "ocr_verdict": evidence.get("ocr_verdict"),
                    "ocr_applied": bool(evidence.get("ocr_applied", False)),
                    "final_url": str(evidence.get("final_url", "") or ""),
                },
            }
        )

    return normalized


def build_dashboard_payload(data_dir: Path) -> Dict[str, Any]:
    blocklist = load_json(data_dir / "blocklist.json", {})
    statistics = load_json(data_dir / "statistics.json", {})
    pipeline_health = load_json(data_dir / "pipeline_health.json", {})
    daily_changes = load_json(data_dir / "domain_changes_daily.json", {"events": []})

    metadata = blocklist.get("metadata", {}) if isinstance(blocklist, dict) else {}
    created_at = str(blocklist.get("created_at", utc_now())) if isinstance(blocklist, dict) else utc_now()
    created_at_dt = parse_utc(created_at) or utc_now_dt()
    window_start = created_at_dt - timedelta(hours=3)

    registry_raw = blocklist.get("domain_registry", []) if isinstance(blocklist, dict) else []
    registry = normalize_registry_entries(registry_raw if isinstance(registry_raw, list) else [])

    new_since_update: List[Dict[str, Any]] = []
    for row in registry:
        last_seen_dt = parse_utc(row.get("last_seen", ""))
        if last_seen_dt and last_seen_dt >= window_start:
            new_since_update.append(row)

    source_methods = sorted(
        {
            source
            for row in registry
            for source in row.get("source_methods", [])
            if isinstance(source, str) and source.strip()
        }
    )

    issue_base = ""
    repo_slug = os.getenv("GITHUB_REPOSITORY", "").strip()
    if repo_slug:
        issue_base = f"https://github.com/{repo_slug}/issues/new"

    issue_links = {
        "false_positive": (
            f"{issue_base}?template=false-positive-report.yml&labels=false-positive,domain-review"
            if issue_base
            else "#"
        ),
        "domain_report": (
            f"{issue_base}?template=domain-report.yml&labels=domain-report"
            if issue_base
            else "#"
        ),
    }

    payload = {
        "generated_at": utc_now(),
        "window_hours": 3,
        "summary": {
            "name": metadata.get("name", "Anti-Judol Indonesia Gambling Blocklist"),
            "description": metadata.get("description", "Operational anti-judol dashboard"),
            "total_active": int((blocklist.get("statistics") or {}).get("total_domains", 0)),
            "lifecycle_counts": ((blocklist.get("statistics") or {}).get("lifecycle_counts") or {}),
            "average_confidence": float((blocklist.get("statistics") or {}).get("average_confidence", 0.0) or 0.0),
            "updated_at": created_at,
        },
        "quality_metrics": (blocklist.get("quality_metrics") or {}),
        "source_metrics": (blocklist.get("source_metrics") or {}),
        "kpi_monthly": (blocklist.get("kpi_monthly") or {}),
        "freshness": (blocklist.get("freshness") or {}),
        "pipeline_health": pipeline_health,
        "statistics": statistics,
        "issue_links": issue_links,
        "source_methods": source_methods,
        "new_since_last_update": {
            "count": len(new_since_update),
            "domains": sorted(new_since_update, key=lambda x: x.get("last_seen", ""), reverse=True)[:250],
        },
        "domains": sorted(registry, key=lambda x: (x.get("lifecycle_status", ""), x.get("risk_score", 0.0)), reverse=True),
        "daily_changelog": daily_changes.get("events", []) if isinstance(daily_changes, dict) else [],
    }

    return payload


def write_index_html(site_dir: Path) -> None:
    html = """<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>Anti-Judol Operations Dashboard</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&family=IBM+Plex+Mono:wght@400;500&display=swap');

    :root {
      --ink: #15201c;
      --bg-top: #d7f5df;
      --bg-bottom: #f6f8f1;
      --panel: rgba(255, 255, 255, 0.84);
      --panel-border: rgba(30, 64, 47, 0.15);
      --text: #0f261c;
      --muted: #4a5f55;
      --active: #0f8a5f;
      --suspect: #c47e16;
      --expired: #7a8490;
      --appealed: #176c9f;
      --accent: #0f8a5f;
      --accent-2: #14532d;
      --chip: #e8f6ee;
      --warn: #f6e4c4;
      --shadow: 0 18px 35px rgba(16, 43, 31, 0.12);
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      color: var(--text);
      font-family: 'Space Grotesk', sans-serif;
      background:
        radial-gradient(1200px 450px at -5% -5%, rgba(15, 138, 95, 0.16), transparent 60%),
        radial-gradient(800px 300px at 105% 0%, rgba(196, 126, 22, 0.14), transparent 60%),
        linear-gradient(170deg, var(--bg-top), var(--bg-bottom));
      min-height: 100vh;
    }

    .container {
      width: min(1200px, 96vw);
      margin: 0 auto;
      padding: 1.2rem 0 2.2rem;
      animation: settle-in 480ms ease-out;
    }

    @keyframes settle-in {
      from { opacity: 0; transform: translateY(8px); }
      to { opacity: 1; transform: translateY(0); }
    }

    .hero {
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 1rem;
      align-items: center;
      margin-bottom: 1rem;
      padding: 1.2rem;
      border-radius: 18px;
      background: linear-gradient(130deg, rgba(255,255,255,0.9), rgba(214,245,222,0.72));
      border: 1px solid var(--panel-border);
      box-shadow: var(--shadow);
    }

    .hero h1 {
      margin: 0;
      font-size: clamp(1.35rem, 2.4vw, 2rem);
      letter-spacing: 0.01em;
    }

    .hero p {
      margin: 0.35rem 0 0;
      color: var(--muted);
    }

    .actions {
      display: flex;
      gap: 0.6rem;
      flex-wrap: wrap;
      justify-content: flex-end;
    }

    .btn {
      appearance: none;
      border: 1px solid rgba(15, 83, 45, 0.18);
      background: white;
      color: var(--accent-2);
      padding: 0.55rem 0.8rem;
      border-radius: 10px;
      font-weight: 600;
      text-decoration: none;
      transition: transform .15s ease, box-shadow .15s ease;
      font-size: 0.92rem;
    }

    .btn:hover {
      transform: translateY(-1px);
      box-shadow: 0 8px 16px rgba(12, 59, 35, 0.16);
    }

    .btn.primary {
      background: linear-gradient(130deg, #0f8a5f, #14532d);
      color: #f4fffa;
      border-color: transparent;
    }

    .grid {
      display: grid;
      gap: 0.8rem;
      grid-template-columns: repeat(12, 1fr);
      margin-bottom: 1rem;
    }

    .card {
      background: var(--panel);
      border: 1px solid var(--panel-border);
      border-radius: 16px;
      padding: 0.95rem;
      box-shadow: var(--shadow);
      backdrop-filter: blur(5px);
    }

    .metric { grid-column: span 3; }
    .metric .label { color: var(--muted); font-size: 0.84rem; }
    .metric .value { font-size: 1.35rem; font-weight: 700; margin-top: .25rem; }

    .wide { grid-column: span 12; }
    .freshness { grid-column: span 6; }
    .changes { grid-column: span 6; }

    .status-chip {
      display: inline-flex;
      align-items: center;
      border-radius: 999px;
      padding: 0.15rem 0.6rem;
      font-size: 0.76rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: .04em;
      margin-right: .3rem;
      background: var(--chip);
    }

    .status-active { color: var(--active); }
    .status-suspect { color: var(--suspect); background: #fff1db; }
    .status-expired { color: var(--expired); background: #eef1f5; }
    .status-appealed { color: var(--appealed); background: #e4f4ff; }

    .mono {
      font-family: 'IBM Plex Mono', monospace;
      font-size: 0.84rem;
      color: #284136;
    }

    .filters {
      display: grid;
      grid-template-columns: 2fr repeat(5, 1fr);
      gap: 0.6rem;
      margin-top: 0.75rem;
    }

    input, select {
      width: 100%;
      border-radius: 9px;
      border: 1px solid rgba(18, 65, 42, 0.2);
      background: #ffffff;
      padding: 0.52rem 0.58rem;
      color: #133427;
      font-family: 'Space Grotesk', sans-serif;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 0.75rem;
      font-size: 0.88rem;
    }

    th, td {
      text-align: left;
      border-bottom: 1px solid rgba(24, 58, 41, 0.12);
      padding: 0.55rem 0.3rem;
      vertical-align: top;
    }

    th {
      color: var(--muted);
      font-weight: 600;
      font-size: 0.77rem;
      text-transform: uppercase;
      letter-spacing: .05em;
    }

    .muted { color: var(--muted); }

    .health {
      display: inline-flex;
      padding: .2rem .6rem;
      border-radius: 999px;
      font-size: .75rem;
      font-weight: 700;
      text-transform: uppercase;
    }

    .healthy { background: #ddf6e9; color: #0b7a4f; }
    .stale { background: var(--warn); color: #98600d; }

    .timeline-item {
      border-top: 1px dashed rgba(20, 54, 39, 0.18);
      padding-top: .55rem;
      margin-top: .55rem;
    }

    @media (max-width: 980px) {
      .hero { grid-template-columns: 1fr; }
      .actions { justify-content: flex-start; }
      .metric { grid-column: span 6; }
      .freshness, .changes { grid-column: span 12; }
      .filters { grid-template-columns: repeat(2, 1fr); }
      .filters .search { grid-column: span 2; }
    }

    @media (max-width: 620px) {
      .metric { grid-column: span 12; }
      .filters { grid-template-columns: 1fr; }
      .filters .search { grid-column: span 1; }
      th:nth-child(6), td:nth-child(6),
      th:nth-child(7), td:nth-child(7) {
        display: none;
      }
    }
  </style>
</head>
<body>
  <main class=\"container\">
    <section class=\"hero\">
      <div>
        <h1 id=\"title\">Anti-Judol Operations Dashboard</h1>
        <p id=\"subtitle\" class=\"muted\">Operational visibility for active, suspect, expired, and appealed domains.</p>
      </div>
      <div class=\"actions\">
        <a id=\"btnFalsePositive\" class=\"btn primary\" href=\"#\">Dispute / False Positive</a>
        <a id=\"btnDomainReport\" class=\"btn\" href=\"#\">Submit Domain Report</a>
        <a class=\"btn\" href=\"api/v1/blocklist.json\">Raw API</a>
      </div>
    </section>

    <section class=\"grid\" id=\"metrics\"></section>

    <section class=\"grid\">
      <article class=\"card freshness\" id=\"freshnessCard\"></article>
      <article class=\"card changes\" id=\"newSinceCard\"></article>
    </section>

    <section class=\"card wide\">
      <h3 style=\"margin-top:0\">Domain Search and Filters</h3>
      <p class=\"muted\" style=\"margin-top:.2rem\">Filter by lifecycle status, confidence, source method, and observed timestamps.</p>
      <div class=\"filters\">
        <input class=\"search\" id=\"searchInput\" placeholder=\"Search domain or evidence signal...\" />
        <select id=\"statusFilter\">
          <option value=\"all\">All Status</option>
          <option value=\"active\">Active</option>
          <option value=\"suspect\">Suspect</option>
          <option value=\"expired\">Expired</option>
          <option value=\"appealed\">Appealed</option>
        </select>
        <select id=\"sourceFilter\">
          <option value=\"all\">All Sources</option>
        </select>
        <input id=\"minConfidence\" type=\"number\" min=\"0\" max=\"100\" value=\"0\" placeholder=\"Min confidence\" />
        <input id=\"firstSeenFilter\" type=\"date\" />
        <input id=\"lastSeenFilter\" type=\"date\" />
      </div>
      <div class=\"mono\" id=\"resultStats\" style=\"margin-top:.65rem\"></div>
      <div style=\"overflow:auto;\">
        <table>
          <thead>
            <tr>
              <th>Domain</th>
              <th>Status</th>
              <th>Confidence</th>
              <th>Sources</th>
              <th>First Seen</th>
              <th>Last Seen</th>
              <th>Evidence</th>
            </tr>
          </thead>
          <tbody id=\"domainRows\"></tbody>
        </table>
      </div>
    </section>

    <section class=\"card wide\" id=\"changelogCard\">
      <h3 style=\"margin-top:0\">Public Daily Changelog</h3>
      <p class=\"muted\">Added, removed, and downgraded domain events from each publication cycle.</p>
      <div id=\"changelogRows\"></div>
    </section>
  </main>

  <script>
    const fmtNum = (v) => Number.isFinite(v) ? v.toLocaleString('en-US') : '-';

    function tsToDate(value) {
      if (!value) return '-';
      const d = new Date(value);
      return Number.isNaN(d.valueOf()) ? value : d.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
    }

    function statusClass(status) {
      const s = (status || '').toLowerCase();
      if (s === 'active') return 'status-active';
      if (s === 'suspect') return 'status-suspect';
      if (s === 'appealed') return 'status-appealed';
      return 'status-expired';
    }

    function renderMetrics(data) {
      const summary = data.summary || {};
      const quality = data.quality_metrics || {};
      const lifecycle = summary.lifecycle_counts || {};
      const disputeRate = Number(quality.dispute_rate || 0) * 100;
      const metrics = [
        ['Active Domains', fmtNum(Number(summary.total_active || 0))],
        ['Average Confidence', fmtNum(Number(summary.average_confidence || 0).toFixed(2)) + '%'],
        ['New Since Last Update', fmtNum(Number((data.new_since_last_update || {}).count || 0))],
        ['Dispute Rate', fmtNum(disputeRate.toFixed(2)) + '%'],
        ['Lifecycle Active', fmtNum(Number(lifecycle.active || 0))],
        ['Lifecycle Suspect', fmtNum(Number(lifecycle.suspect || 0))],
        ['Lifecycle Expired', fmtNum(Number(lifecycle.expired || 0))],
        ['Lifecycle Appealed', fmtNum(Number(lifecycle.appealed || 0))],
      ];

      document.getElementById('metrics').innerHTML = metrics.map(([label, value]) => `
        <article class=\"card metric\">
          <div class=\"label\">${label}</div>
          <div class=\"value\">${value}</div>
        </article>
      `).join('');
    }

    function renderFreshness(data) {
      const freshness = data.freshness || {};
      const health = data.pipeline_health || {};
      const status = String(health.status || 'unknown').toLowerCase();

      document.getElementById('freshnessCard').innerHTML = `
        <h3 style=\"margin-top:0\">Data Freshness Panel</h3>
        <div style=\"margin-bottom:.45rem\">
          <span class=\"health ${status === 'healthy' ? 'healthy' : 'stale'}\">${status}</span>
        </div>
        <div class=\"mono\">Hunt last success: ${tsToDate(freshness.hunt_last_success_at)}</div>
        <div class=\"mono\">Verify last success: ${tsToDate(freshness.verify_last_success_at)}</div>
        <div class=\"mono\">Publish last success: ${tsToDate(freshness.publish_last_success_at)}</div>
        <div class=\"mono\" style=\"margin-top:.45rem\">Hunt age hours: ${freshness.hunt_age_hours ?? '-'}</div>
        <div class=\"mono\">Verify age hours: ${freshness.verify_age_hours ?? '-'}</div>
      `;
    }

    function renderNewSince(data) {
      const payload = data.new_since_last_update || {};
      const list = Array.isArray(payload.domains) ? payload.domains.slice(0, 12) : [];

      document.getElementById('newSinceCard').innerHTML = `
        <h3 style=\"margin-top:0\">New Since Last Update (3h)</h3>
        <p class=\"muted\" style=\"margin:.1rem 0 .5rem\">${fmtNum(Number(payload.count || 0))} domains observed in the rolling 3-hour window.</p>
        ${list.length ? list.map((row) => `
          <div class=\"timeline-item\">
            <div><strong>${row.domain}</strong></div>
            <div class=\"mono\">${tsToDate(row.last_seen)} | ${String(row.lifecycle_status || '').toUpperCase()}</div>
          </div>
        `).join('') : '<div class=\"muted\">No new domain in this window.</div>'}
      `;
    }

    function buildSourceOptions(sourceMethods) {
      const sel = document.getElementById('sourceFilter');
      const options = ['<option value=\"all\">All Sources</option>'];
      for (const src of sourceMethods || []) {
        options.push(`<option value=\"${src}\">${src}</option>`);
      }
      sel.innerHTML = options.join('');
    }

    function applyFilters(data) {
      const q = document.getElementById('searchInput').value.trim().toLowerCase();
      const status = document.getElementById('statusFilter').value;
      const source = document.getElementById('sourceFilter').value;
      const minConfidence = Number(document.getElementById('minConfidence').value || 0);
      const firstSeen = document.getElementById('firstSeenFilter').value;
      const lastSeen = document.getElementById('lastSeenFilter').value;

      const domains = Array.isArray(data.domains) ? data.domains : [];
      const out = domains.filter((row) => {
        const domain = String(row.domain || '').toLowerCase();
        const lifecycle = String(row.lifecycle_status || '').toLowerCase();
        const conf = Number(row.confidence || 0);
        const sources = Array.isArray(row.source_methods) ? row.source_methods : [];
        const evidence = row.evidence || {};

        const evidenceText = [
          ...(Array.isArray(evidence.top_danger_signals) ? evidence.top_danger_signals : []),
          String(evidence.ocr_verdict || ''),
          String(evidence.final_url || ''),
          ...sources,
        ].join(' ').toLowerCase();

        if (q && !domain.includes(q) && !evidenceText.includes(q)) return false;
        if (status !== 'all' && lifecycle !== status) return false;
        if (source !== 'all' && !sources.includes(source)) return false;
        if (conf < minConfidence) return false;

        const firstSeenDate = String(row.first_seen || '').slice(0, 10);
        const lastSeenDate = String(row.last_seen || '').slice(0, 10);

        if (firstSeen && firstSeenDate && firstSeenDate < firstSeen) return false;
        if (lastSeen && lastSeenDate && lastSeenDate > lastSeen) return false;

        return true;
      });

      return out;
    }

    function renderRows(data) {
      const filtered = applyFilters(data);
      const maxRows = 500;
      const rows = filtered.slice(0, maxRows);

      document.getElementById('resultStats').textContent = `${fmtNum(filtered.length)} matched domains` + (filtered.length > maxRows ? ` (showing first ${maxRows})` : '');

      document.getElementById('domainRows').innerHTML = rows.map((row) => {
        const ev = row.evidence || {};
        const danger = Array.isArray(ev.top_danger_signals) ? ev.top_danger_signals.slice(0, 4).join(', ') : '-';
        const sources = Array.isArray(row.source_methods) ? row.source_methods.join(', ') : '-';

        return `
          <tr>
            <td><strong>${row.domain}</strong><div class=\"mono\">risk: ${Number(row.risk_score || 0).toFixed(4)}</div></td>
            <td><span class=\"status-chip ${statusClass(row.lifecycle_status)}\">${String(row.lifecycle_status || '').toUpperCase()}</span></td>
            <td>${Number(row.confidence || 0).toFixed(2)}%</td>
            <td class=\"mono\">${sources || '-'}</td>
            <td class=\"mono\">${String(row.first_seen || '').slice(0, 19).replace('T', ' ') || '-'}</td>
            <td class=\"mono\">${String(row.last_seen || '').slice(0, 19).replace('T', ' ') || '-'}</td>
            <td>
              <div>${danger || '-'}</div>
              <div class=\"mono\">OCR: ${ev.ocr_verdict || 'n/a'} | pay: ${ev.payment_hits || 0} | msg: ${ev.messaging_hits || 0}</div>
            </td>
          </tr>
        `;
      }).join('');
    }

    function renderChangelog(data) {
      const events = Array.isArray(data.daily_changelog) ? data.daily_changelog.slice(-20).reverse() : [];

      const html = events.length
        ? events.map((ev) => `
            <div class=\"timeline-item\">
              <div><strong>${ev.date || '-'} ${ev.timestamp ? '(' + tsToDate(ev.timestamp) + ')' : ''}</strong></div>
              <div class=\"mono\">Added: ${(ev.counts || {}).added || 0} | Removed: ${(ev.counts || {}).removed || 0} | Downgraded: ${(ev.counts || {}).downgraded || 0}</div>
              <div class=\"mono\">Samples: ${(Array.isArray(ev.added) ? ev.added.slice(0, 4).join(', ') : '') || '-'}</div>
            </div>
          `).join('')
        : '<div class=\"muted\">No changelog event available yet.</div>';

      document.getElementById('changelogRows').innerHTML = html;
    }

    function bindFilters(data) {
      const ids = ['searchInput', 'statusFilter', 'sourceFilter', 'minConfidence', 'firstSeenFilter', 'lastSeenFilter'];
      for (const id of ids) {
        document.getElementById(id).addEventListener('input', () => renderRows(data));
        document.getElementById(id).addEventListener('change', () => renderRows(data));
      }
    }

    async function main() {
      const res = await fetch('api/v1/dashboard.json', { cache: 'no-store' });
      const data = await res.json();

      document.getElementById('title').textContent = (data.summary || {}).name || 'Anti-Judol Operations Dashboard';
      document.getElementById('subtitle').textContent = (data.summary || {}).description || 'Operational anti-judol dashboard';

      const links = data.issue_links || {};
      document.getElementById('btnFalsePositive').href = links.false_positive || '#';
      document.getElementById('btnDomainReport').href = links.domain_report || '#';

      renderMetrics(data);
      renderFreshness(data);
      renderNewSince(data);
      buildSourceOptions(data.source_methods || []);
      renderRows(data);
      renderChangelog(data);
      bindFilters(data);
    }

    main().catch((err) => {
      document.body.innerHTML = `<main class=\"container\"><section class=\"card\"><h2>Dashboard Load Error</h2><p>${String(err)}</p></section></main>`;
    });
  </script>
</body>
</html>
"""

    (site_dir / "index.html").write_text(html, encoding="utf-8")


def write_manifest(site_dir: Path, copied: Dict[str, str], summary: Dict[str, Any]) -> None:
    payload = {
        "generated_at": utc_now(),
        "files": copied,
        "summary": summary,
    }
    (site_dir / "manifest.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build static Pages artifact from data outputs")
    parser.add_argument("--data-dir", default="data", help="Directory containing generated outputs")
    parser.add_argument("--site-dir", default="site", help="Directory to build static site artifact")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    data_dir = Path(args.data_dir)
    site_dir = Path(args.site_dir)

    if not data_dir.exists():
        raise FileNotFoundError(f"Data directory not found: {data_dir}")

    if site_dir.exists():
        shutil.rmtree(site_dir)
    site_dir.mkdir(parents=True, exist_ok=True)

    copied = copy_required_files(data_dir, site_dir)
    dashboard = build_dashboard_payload(data_dir)

    dashboard_path = site_dir / "api" / "v1" / "dashboard.json"
    dashboard_path.parent.mkdir(parents=True, exist_ok=True)
    dashboard_path.write_text(json.dumps(dashboard, indent=2), encoding="utf-8")
    copied["dashboard.json"] = dashboard_path.relative_to(site_dir).as_posix()

    write_index_html(site_dir)
    write_manifest(site_dir, copied, dashboard.get("summary", {}))

    print(json.dumps({"site_dir": str(site_dir), "files": copied, "generated_at": utc_now()}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
