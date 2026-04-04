const BASE_CORS_HEADERS = {
  "Access-Control-Allow-Methods": "POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type,Authorization,X-Webhook-Secret",
  "Content-Type": "application/json",
};

const DOMAIN_REGEX = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;

function buildCorsHeaders(request, env) {
  const configured = String(env.ALLOWED_ORIGINS || "*")
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);

  const origin = request.headers.get("Origin") || "";
  let allowOrigin = "*";

  if (configured.length > 0 && !(configured.length === 1 && configured[0] === "*")) {
    if (origin && configured.includes(origin)) {
      allowOrigin = origin;
    } else {
      // Keep deterministic response while still restricting to configured origins.
      allowOrigin = configured[0];
    }
  }

  return {
    ...BASE_CORS_HEADERS,
    "Access-Control-Allow-Origin": allowOrigin,
    Vary: "Origin",
  };
}

function jsonResponse(request, env, payload, status = 200) {
  return new Response(JSON.stringify(payload), { status, headers: buildCorsHeaders(request, env) });
}

function normalizeDomain(input) {
  const value = String(input || "").trim().toLowerCase();
  if (!value) return "";

  try {
    const url = value.includes("://") ? new URL(value) : new URL(`https://${value}`);
    return url.hostname.replace(/^www\./, "");
  } catch {
    return value.replace(/^www\./, "");
  }
}

async function enforceRateLimit(env, clientIp, maxPerHour = 10) {
  const allowBypass = String(env.ALLOW_RATE_LIMIT_BYPASS || "").toLowerCase() === "true";
  if (!env.RATE_LIMIT_KV) {
    if (allowBypass) {
      return { allowed: true, remaining: maxPerHour };
    }
    return { allowed: false, remaining: 0, reason: "rate_limit_backend_unavailable" };
  }

  const hourBucket = new Date().toISOString().slice(0, 13);
  const key = `rate:${clientIp}:${hourBucket}`;

  const currentRaw = await env.RATE_LIMIT_KV.get(key);
  const current = Number(currentRaw || "0");

  if (current >= maxPerHour) {
    return { allowed: false, remaining: 0 };
  }

  const next = current + 1;
  await env.RATE_LIMIT_KV.put(key, String(next), { expirationTtl: 3600 });
  return { allowed: true, remaining: maxPerHour - next };
}

function maskEmail(input) {
  const value = String(input || "").trim().toLowerCase();
  if (!value.includes("@")) return "Anonymous";
  const [local, domain] = value.split("@", 2);
  const localVisible = local.slice(0, 2);
  return `${localVisible}${"*".repeat(Math.max(1, local.length - localVisible.length))}@${domain}`;
}

async function sha256Hex(value) {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(String(value || ""));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function normalizeEvidenceUrl(input) {
  const value = String(input || "").trim();
  if (!value) return "";
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return "";
    }
    return parsed.toString().slice(0, 2048);
  } catch {
    return "";
  }
}

function isAuthorized(request, env) {
  const expected = String(env.WEBHOOK_SHARED_SECRET || "").trim();
  if (!expected) {
    return false;
  }

  const auth = String(request.headers.get("Authorization") || "").trim();
  const bearer = auth.toLowerCase().startsWith("bearer ") ? auth.slice(7).trim() : "";
  const headerSecret = String(request.headers.get("X-Webhook-Secret") || "").trim();

  return bearer === expected || headerSecret === expected;
}

async function getRecentDomainReport(env, domain) {
  if (!env.RATE_LIMIT_KV) return null;

  const hourBucket = new Date().toISOString().slice(0, 13);
  const key = `report:${domain}:${hourBucket}`;
  const raw = await env.RATE_LIMIT_KV.get(key);
  if (!raw) return null;

  try {
    const parsed = JSON.parse(raw);
    if (parsed && parsed.issue_number && parsed.issue_url) {
      return parsed;
    }
  } catch {
    return null;
  }

  return null;
}

async function saveRecentDomainReport(env, domain, issuePayload) {
  if (!env.RATE_LIMIT_KV) return;

  const hourBucket = new Date().toISOString().slice(0, 13);
  const key = `report:${domain}:${hourBucket}`;
  await env.RATE_LIMIT_KV.put(key, JSON.stringify(issuePayload), { expirationTtl: 3600 });
}

async function createGithubIssue(env, payload) {
  const owner = env.GITHUB_OWNER;
  const repo = env.GITHUB_REPO || "hanzantijudol";
  const token = env.GITHUB_TOKEN;

  if (!owner || !repo || !token) {
    throw new Error("Missing GitHub credentials: GITHUB_OWNER/GITHUB_REPO/GITHUB_TOKEN");
  }

  const title = `[DOMAIN REPORT] ${payload.domain}`;
  const body = [
    "## Domain Report",
    "",
    `Domain: ${payload.domain}`,
    `Evidence URL: ${payload.evidence_url || "N/A"}`,
    `Reporter: ${payload.reporter_identity || "Anonymous"}`,
    `Reporter Fingerprint: ${payload.reporter_fingerprint || "N/A"}`,
    `Timestamp: ${new Date().toISOString()}`,
    "",
    "This issue is auto-generated by Cloudflare Worker webhook.",
    "It triggers the main verify workflow for unified DOM + OCR analysis.",
  ].join("\n");

  const response = await fetch(`https://api.github.com/repos/${owner}/${repo}/issues`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "Content-Type": "application/json",
      "User-Agent": "antijudol-ocr-worker",
    },
    body: JSON.stringify({
      title,
      body,
      labels: ["domain-report", "user-report"],
    }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`GitHub API error (${response.status}): ${errorText}`);
  }

  const issue = await response.json();
  return {
    issue_number: issue.number,
    issue_url: issue.html_url,
  };
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: buildCorsHeaders(request, env) });
    }

    const url = new URL(request.url);
    if (url.pathname !== "/api/report-domain") {
      return jsonResponse(request, env, { status: "error", message: "Not found" }, 404);
    }

    if (request.method !== "POST") {
      return jsonResponse(request, env, { status: "error", message: "Method not allowed" }, 405);
    }

    if (!isAuthorized(request, env)) {
      return jsonResponse(request, env, { status: "error", message: "Unauthorized webhook request" }, 401);
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return jsonResponse(request, env, { status: "error", message: "Invalid JSON payload" }, 400);
    }

    const domain = normalizeDomain(body.domain);
    if (!domain || !DOMAIN_REGEX.test(domain)) {
      return jsonResponse(request, env, { status: "error", message: "Invalid or missing domain" }, 400);
    }

    const evidenceUrl = normalizeEvidenceUrl(body.evidence_url);
    if (String(body.evidence_url || "").trim() && !evidenceUrl) {
      return jsonResponse(request, env, { status: "error", message: "Invalid evidence_url" }, 400);
    }

    const sourceIp = request.headers.get("CF-Connecting-IP") || "unknown";
    const rate = await enforceRateLimit(env, sourceIp, 10);
    if (!rate.allowed) {
      const backendUnavailable = rate.reason === "rate_limit_backend_unavailable";
      return jsonResponse(
        request,
        env,
        {
          status: "error",
          message: backendUnavailable
            ? "Rate limit backend unavailable. Request rejected for safety."
            : "Rate limit exceeded. Max 10 requests per hour per IP.",
        },
        backendUnavailable ? 503 : 429,
      );
    }

    const duplicate = await getRecentDomainReport(env, domain);
    if (duplicate) {
      return jsonResponse(
        request,
        env,
        {
          status: "ok",
          duplicate: true,
          message: "Domain already reported in current time window; reusing existing issue.",
          issue_number: duplicate.issue_number,
          issue_url: duplicate.issue_url,
          rate_limit_remaining: rate.remaining,
        },
        200,
      );
    }

    const reporterEmail = String(body.user_email || "").trim().toLowerCase();
    const reporterFingerprint = (await sha256Hex(`${reporterEmail}|${sourceIp}`)).slice(0, 16);

    try {
      const githubIssue = await createGithubIssue(env, {
        domain,
        evidence_url: evidenceUrl,
        reporter_identity: maskEmail(reporterEmail),
        reporter_fingerprint: reporterFingerprint,
      });

      await saveRecentDomainReport(env, domain, githubIssue);

      return jsonResponse(request, env, {
        status: "ok",
        message: "Domain report accepted. Unified verification will start via GitHub issue trigger.",
        issue_number: githubIssue.issue_number,
        issue_url: githubIssue.issue_url,
        rate_limit_remaining: rate.remaining,
      });
    } catch (error) {
      return jsonResponse(
        request,
        env,
        {
          status: "error",
          message: "Failed to create GitHub issue",
          detail: String(error.message || error),
        },
        502,
      );
    }
  },
};
