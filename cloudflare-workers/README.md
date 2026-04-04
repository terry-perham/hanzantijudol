# OCR Webhook Worker

Cloudflare Worker endpoint untuk menerima report domain lalu auto-create GitHub issue berlabel domain-report.

Kebijakan endpoint:
- Public internet endpoint: YES
- Rate limit backend (KV): WAJIB
- Shared secret auth: WAJIB di production
- Deploy branch target: main only

## Endpoint

- Method: POST
- Path: /api/report-domain
- Body JSON:

{
  "domain": "example.com",
  "evidence_url": "https://...",
  "user_email": "reporter@example.com"
}

## Required Env / Secrets

- GITHUB_OWNER
- GITHUB_REPO
- GITHUB_TOKEN (secret)
- WEBHOOK_SHARED_SECRET (secret)
- RATE_LIMIT_KV (KV binding)

## Optional Env

- ALLOWED_ORIGINS (default `*`, rekomendasi production: origin frontend spesifik)
- ALLOW_RATE_LIMIT_BYPASS (default `false`, hanya untuk local dev)

## Setup

1. Login Cloudflare:
   wrangler login

2. Buat KV namespace:
   wrangler kv namespace create RATE_LIMIT_KV
   wrangler kv namespace create RATE_LIMIT_KV --preview

3. Update ID namespace di wrangler.toml.

4. Set secret token GitHub:
   wrangler secret put GITHUB_TOKEN

5. Set secret webhook auth:
   wrangler secret put WEBHOOK_SHARED_SECRET

6. Deploy:
   wrangler deploy

## GitHub Actions Deploy

Workflow deploy sudah diintegrasikan ke:
- .github/workflows/verify.yml (job: deploy-webhook, trigger push path cloudflare-workers/**)

Required repository secrets:
- CLOUDFLARE_API_TOKEN
- CLOUDFLARE_ACCOUNT_ID
- CLOUDFLARE_GITHUB_OWNER
- CLOUDFLARE_GITHUB_REPO
- CLOUDFLARE_GITHUB_TOKEN
- CLOUDFLARE_WEBHOOK_SHARED_SECRET

Required repository variables:
- CLOUDFLARE_RATE_LIMIT_KV_ID
- CLOUDFLARE_RATE_LIMIT_KV_PREVIEW_ID

Optional repository variables:
- none

## Verification

curl -X POST https://<worker-subdomain>.workers.dev/api/report-domain \
  -H "Content-Type: application/json" \
   -H "Authorization: Bearer <WEBHOOK_SHARED_SECRET>" \
  -d '{"domain":"example.com"}'

Jika sukses, response berisi issue_number dan issue_url.

Catatan privasi:
- Worker tidak lagi menuliskan email mentah dan IP mentah ke issue body.
- Issue menyimpan masked reporter identity + fingerprint hash untuk tetap bisa ditracking tanpa membuka PII.

Issue yang dibuat akan diproses oleh workflow utama:
- .github/workflows/verify.yml
