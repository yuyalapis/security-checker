"""Low-impact external web service security check API."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, field_validator

app = FastAPI(
    title="Web Security Checker",
    description="Low-impact HTTP/TLS baseline checks for services you are authorized to assess.",
    version="1.0.0",
)

TIMEOUT = httpx.Timeout(8.0, connect=4.0)
MAX_REDIRECTS = 4
MAX_RESPONSE_BYTES = 1024 * 1024


class ScanRequest(BaseModel):
    url: str = Field(..., description="HTTP or HTTPS URL to assess")
    authorized: bool = Field(
        ..., description="Confirm that you are authorized to assess this service"
    )

    @field_validator("url")
    @classmethod
    def normalize_url(cls, value: str) -> str:
        value = value.strip()
        parsed = urlparse(value)
        if parsed.scheme not in {"https", "http"} or not parsed.hostname:
            raise ValueError("url must be a complete URL beginning with http:// or https://")
        if parsed.username or parsed.password:
            raise ValueError("Do not include a username or password in the URL")
        if parsed.port and not 1 <= parsed.port <= 65535:
            raise ValueError("Invalid port number")
        return value


async def validate_public_target(url: str) -> None:
    """Check all resolved IPs and block localhost/private network destinations."""
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        raise ValueError("Missing hostname")
    try:
        literal = ipaddress.ip_address(host)
        addresses = [literal]
    except ValueError:
        try:
            records = await asyncio.get_running_loop().getaddrinfo(
                host, parsed.port or (443 if parsed.scheme == "https" else 80),
                type=socket.SOCK_STREAM,
            )
        except socket.gaierror as exc:
            raise ValueError("Unable to resolve hostname") from exc
        addresses = list({ipaddress.ip_address(record[4][0]) for record in records})
    if not addresses or any(not address.is_global for address in addresses):
        raise ValueError("Only publicly routable internet hosts can be assessed")


async def request_without_unsafe_redirects(url: str) -> tuple[httpx.Response, str, int]:
    """Validate each redirect target and issue one GET request per hop."""
    current = url
    async with httpx.AsyncClient(
        timeout=TIMEOUT,
        follow_redirects=False,
        verify=True,
        headers={"User-Agent": "WebSecurityChecker/1.0 (authorized security review)"},
    ) as client:
        for redirects in range(MAX_REDIRECTS + 1):
            await validate_public_target(current)
            try:
                async with client.stream("GET", current) as response:
                    if response.status_code in {301, 302, 303, 307, 308}:
                        location = response.headers.get("location")
                        if not location:
                            return response, current, redirects
                        if redirects == MAX_REDIRECTS:
                            raise ValueError("Maximum redirect count exceeded")
                        current = urljoin(current, location)
                        continue
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > MAX_RESPONSE_BYTES:
                            body = body[:MAX_RESPONSE_BYTES]
                            break
                    # Preserve the response content after the streaming context closes.
                    response._content = bytes(body)
                    return response, current, redirects
            except httpx.RequestError as exc:
                raise ValueError(f"Unable to connect to target: {type(exc).__name__}") from exc
    raise ValueError("Request failed")


def analyze_headers(headers: httpx.Headers, final_url: str) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    is_https = urlparse(final_url).scheme == "https"
    expected = {
        "strict-transport-security": (is_https, "Configure HSTS for HTTPS connections"),
        "content-security-policy": (True, "Configure Content-Security-Policy to restrict permitted content sources"),
        "x-content-type-options": (True, "Set X-Content-Type-Options: nosniff"),
        "referrer-policy": (True, "Set a Referrer-Policy"),
        "permissions-policy": (True, "Set a Permissions-Policy and disable browser features you do not need"),
    }
    normalized = {key.lower(): value for key, value in headers.items()}
    for header, (applicable, recommendation) in expected.items():
        present = header in normalized
        if not applicable:
            status, severity = "not_applicable", "info"
        elif present:
            status, severity = "present", "info"
        else:
            status, severity = "missing", "medium"
        checks.append({
            "id": f"header_{header.replace('-', '_')}",
            "status": status,
            "severity": severity,
            "observed": normalized.get(header),
            "recommendation": recommendation if status == "missing" else None,
        })

    if not is_https:
        checks.append({
            "id": "https", "status": "missing", "severity": "high",
            "observed": final_url,
            "recommendation": "Enable HTTPS before handling credentials or sensitive data",
        })
    else:
        checks.append({"id": "https", "status": "present", "severity": "info", "observed": True})

    server = normalized.get("server")
    checks.append({
        "id": "server_banner",
        "status": "disclosed" if server else "not_disclosed",
        "severity": "low" if server else "info",
        "observed": server,
        "recommendation": "Minimize product and version details in the Server header" if server else None,
    })

    set_cookie_values = headers.get_list("set-cookie")
    cookie_findings = []
    for value in set_cookie_values:
        lower = value.lower()
        missing = [flag for flag, ok in (
            ("Secure", "secure" in lower),
            ("HttpOnly", "httponly" in lower),
            ("SameSite", "samesite" in lower),
        ) if not ok]
        cookie_findings.append({"cookie_name": value.split("=", 1)[0].strip(), "missing": missing})
    checks.append({
        "id": "cookie_flags",
        "status": "review" if any(item["missing"] for item in cookie_findings) else "ok",
        "severity": "medium" if any(item["missing"] for item in cookie_findings) else "info",
        "observed": cookie_findings,
        "recommendation": "Set Secure, HttpOnly, and an appropriate SameSite attribute on session cookies"
        if any(item["missing"] for item in cookie_findings) else None,
    })
    return checks


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/scan")
async def scan(request: ScanRequest) -> dict[str, Any]:
    """Check baseline configuration for a single URL using GET only."""
    if not request.authorized:
        raise HTTPException(status_code=400, detail="Authorization acknowledgment is required")
    try:
        await validate_public_target(request.url)
        started = time.monotonic()
        response, final_url, redirects = await request_without_unsafe_redirects(request.url)
        duration_ms = round((time.monotonic() - started) * 1000)
        findings = analyze_headers(response.headers, final_url)
        return {
            "target": request.url,
            "final_url": final_url,
            "http_status": response.status_code,
            "duration_ms": duration_ms,
            "redirect_count": redirects,
            "checks": findings,
            "summary": {
                "total": len(findings),
                "high": sum(item["severity"] == "high" and item["status"] == "missing" for item in findings),
                "medium": sum(item["severity"] == "medium" and item["status"] in {"missing", "review"} for item in findings),
                "low": sum(item["severity"] == "low" for item in findings),
            },
            "scope": "Baseline checks using GET requests; this does not guarantee the absence of vulnerabilities.",
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
