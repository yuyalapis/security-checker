# Web Security Checker

A low-impact HTTP/TLS baseline checker for company-owned services that you are authorized to assess. Built with FastAPI, it sends a regular `GET` request to one URL (and follows redirects within a small limit). It does not send exploit payloads, scan ports, or attempt authentication bypasses.

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Interactive API documentation is available at <http://127.0.0.1:8000/docs>.

## Scan a URL

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scan \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com","authorized":true}'
```

The scan checks HTTPS usage, common security headers, cookie attributes, and the `Server` banner. It rejects DNS results that are not public IP addresses and applies the same check to redirect targets. TLS certificate verification is enabled, and response bodies are limited to 1 MiB.

## Operational notes

- `authorized: true` is an acknowledgment field, not authentication or access control.
- Before exposing this API to the internet, add API authentication, rate limiting, and per-user audit logging.
- In production, restrict targets to an allowlist of domains instead of allowing arbitrary URLs.
- Results are configuration guidance; they do not prove that an application is free of vulnerabilities.
