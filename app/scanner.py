"""
scanner.py
Async crawler + vulnerability checks. Runs as a background task per scan_id,
mutating a shared in-memory ScanState that main.py exposes via /scan/{id}/status.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import httpx

from app.auth import Session

SQLI_PAYLOADS = ["'", "\"", "')--", "' OR '1'='1", "\" OR \"1\"=\"1"]
XSS_PAYLOAD = "<script>alert(1)</script>"

SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "sqlstate",
    "pg_query():",
    "postgresql error",
    "ora-00933",
    "ora-01756",
    "microsoft odbc",
    "odbc sql server driver",
    "sqlite3::query",
    "sqlite error",
    "syntax error at or near",
    "mysql_fetch_array()",
    "supplied argument is not a valid mysql",
]

SENSITIVE_PATHS = [
    ".env",
    ".git/config",
    "backup.zip",
    "admin",
    "phpinfo.php",
    "server-status",
]

SECURITY_HEADERS = {
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options",
    "strict-transport-security": "HSTS (Strict-Transport-Security)",
    "x-content-type-options": "X-Content-Type-Options",
}

MAX_CRAWL_PAGES = 25
REQUEST_TIMEOUT = 12.0


@dataclass
class Finding:
    severity: str          # High | Medium | Low | Info
    vuln_type: str
    url: str
    parameter: str
    payload: str
    evidence: str


@dataclass
class ScanState:
    scan_id: str
    stage: str = "Queued"
    progress: int = 0          # 0-100
    total_steps: int = 1
    done_steps: int = 0
    results: list = field(default_factory=list)   # list[Finding] (as dicts)
    errors: list = field(default_factory=list)
    finished: bool = False

    def add_finding(self, f: Finding):
        self.results.append(
            {
                "severity": f.severity,
                "vuln_type": f.vuln_type,
                "url": f.url,
                "parameter": f.parameter,
                "payload": f.payload,
                "evidence": f.evidence,
            }
        )

    def add_error(self, msg: str):
        self.errors.append(msg)

    def set_stage(self, stage: str):
        self.stage = stage

    def bump_progress(self):
        self.done_steps += 1
        if self.total_steps > 0:
            self.progress = min(100, int((self.done_steps / self.total_steps) * 100))

    def to_dict(self):
        return {
            "scan_id": self.scan_id,
            "stage": self.stage,
            "progress": self.progress,
            "results": self.results,
            "errors": self.errors,
            "finished": self.finished,
        }


def _client_kwargs(session: Optional[Session]) -> dict:
    kwargs = {"timeout": REQUEST_TIMEOUT, "follow_redirects": True, "verify": False}
    if session:
        if session.cookies:
            kwargs["cookies"] = session.cookies
        if session.headers:
            kwargs["headers"] = dict(session.headers)
    return kwargs


def _add_param(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    q = parse_qs(parsed.query)
    q[name] = [value]
    new_query = urlencode(q, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _extract_links(base_url: str, html: str) -> list:
    links = set()
    for m in re.finditer(r'href=["\']([^"\'#]+)["\']', html, re.IGNORECASE):
        href = m.group(1)
        if href.startswith(("mailto:", "javascript:", "tel:")):
            continue
        full = urljoin(base_url, href)
        parsed = urlparse(full)
        base_parsed = urlparse(base_url)
        if parsed.netloc == base_parsed.netloc and parsed.scheme in ("http", "https"):
            links.add(full)
    return list(links)


def _extract_params(url: str) -> list:
    parsed = urlparse(url)
    q = parse_qs(parsed.query)
    return list(q.keys())


async def run_scan(
    state: ScanState,
    target_url: str,
    authenticated: bool,
    session: Optional[Session],
    urls_to_scan: list,
    also_crawl: bool,
):
    """Main orchestration: crawl (optional) -> scan each URL -> headers -> auth-bypass."""
    try:
        state.set_stage("Preparing")

        all_urls = list(dict.fromkeys(urls_to_scan))  # de-dup, preserve order

        if also_crawl and target_url:
            state.set_stage("Crawling")
            try:
                crawled = await _crawl(target_url, session)
                for u in crawled:
                    if u not in all_urls:
                        all_urls.append(u)
            except Exception as e:
                state.add_error(f"Crawling failed: {e}")

        if not all_urls:
            if target_url:
                all_urls = [target_url]
            else:
                state.add_error("No URLs to scan were provided.")
                state.set_stage("Done")
                state.finished = True
                return

        all_urls = all_urls[:MAX_CRAWL_PAGES]

        # Step budget: per-url vuln checks + header check + (optional) auth bypass check
        steps_per_url = 2  # vuln checks + header check
        if authenticated and session and not session.is_empty():
            steps_per_url += 1  # auth bypass check
        state.total_steps = max(1, len(all_urls) * steps_per_url)
        state.done_steps = 0

        async with httpx.AsyncClient(**_client_kwargs(session)) as client:
            for idx, url in enumerate(all_urls, start=1):
                state.set_stage(f"Scanning URL {idx}/{len(all_urls)}")

                try:
                    resp = await client.get(url)
                except Exception as e:
                    state.add_error(f"Request failed for {url}: {e}")
                    state.bump_progress()
                    state.bump_progress()
                    continue

                body = resp.text if resp.content else ""

                # --- Session-expiry detection (authenticated mode) ---
                if authenticated and _looks_logged_out(resp.status_code, body):
                    state.add_error(
                        f"Session expired or invalid while scanning {url} — stopping scan."
                    )
                    break

                await _check_vulnerabilities(client, url, body, state)
                state.bump_progress()

                await _check_sensitive_paths(client, url, state)

                await _check_security_headers(url, resp, state)
                state.bump_progress()

                if authenticated and session and not session.is_empty():
                    await _check_auth_bypass(url, resp, state)
                    state.bump_progress()

        state.set_stage("Done")
        state.progress = 100
        state.finished = True

    except Exception as e:
        state.add_error(f"Unexpected scan error: {e}")
        state.set_stage("Error")
        state.finished = True


def _looks_logged_out(status_code: int, body: str) -> bool:
    if status_code in (401, 403):
        return True
    lowered = body.lower()
    markers = ["please log in", "please sign in", "session expired", "your session has expired"]
    return any(m in lowered for m in markers)


async def _crawl(target_url: str, session: Optional[Session]) -> list:
    discovered = [target_url]
    seen = set()
    async with httpx.AsyncClient(**_client_kwargs(session)) as client:
        try:
            resp = await client.get(target_url)
        except Exception:
            return discovered
        if resp.status_code >= 400:
            return discovered
        links = _extract_links(target_url, resp.text)
        for link in links:
            if link not in seen:
                seen.add(link)
                discovered.append(link)
            if len(discovered) >= MAX_CRAWL_PAGES:
                break
    return discovered


async def _check_vulnerabilities(client: httpx.AsyncClient, url: str, body: str, state: ScanState):
    params = _extract_params(url)

    if not params:
        # No query params to fuzz on this URL; still worth noting for info purposes.
        return

    for param in params:
        # --- SQL Injection ---
        for payload in SQLI_PAYLOADS:
            test_url = _add_param(url, param, payload)
            try:
                resp = await client.get(test_url)
            except Exception:
                continue
            lowered = resp.text.lower()
            hit = next((sig for sig in SQL_ERROR_SIGNATURES if sig in lowered), None)
            if hit:
                state.add_finding(
                    Finding(
                        severity="High",
                        vuln_type="SQL Injection",
                        url=test_url,
                        parameter=param,
                        payload=payload,
                        evidence=f"Database error signature detected: '{hit}'",
                    )
                )
                break  # one SQLi finding per param is enough

        # --- Reflected XSS ---
        test_url = _add_param(url, param, XSS_PAYLOAD)
        try:
            resp = await client.get(test_url)
            if XSS_PAYLOAD in resp.text:
                state.add_finding(
                    Finding(
                        severity="High",
                        vuln_type="Reflected XSS",
                        url=test_url,
                        parameter=param,
                        payload=XSS_PAYLOAD,
                        evidence="Payload was reflected unescaped in the response body.",
                    )
                )
        except Exception:
            pass


async def _check_sensitive_paths(client: httpx.AsyncClient, url: str, state: ScanState):
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    for path in SENSITIVE_PATHS:
        probe_url = f"{base}/{path}"
        try:
            resp = await client.get(probe_url)
        except Exception:
            continue
        if resp.status_code == 200 and len(resp.content) > 0:
            non_trivial = len(resp.text.strip()) > 20
            looks_like_error_page = any(
                marker in resp.text.lower()
                for marker in ["404", "not found", "page not found"]
            )
            if non_trivial and not looks_like_error_page:
                state.add_finding(
                    Finding(
                        severity="Medium",
                        vuln_type="Sensitive File/Directory Exposure",
                        url=probe_url,
                        parameter="-",
                        payload="-",
                        evidence=f"HTTP {resp.status_code}, {len(resp.content)} bytes returned.",
                    )
                )


async def _check_security_headers(url: str, resp: httpx.Response, state: ScanState):
    present = {k.lower() for k in resp.headers.keys()}
    missing = []
    for header_key, label in SECURITY_HEADERS.items():
        if header_key not in present:
            missing.append(label)
    if missing:
        state.add_finding(
            Finding(
                severity="Low",
                vuln_type="Missing Security Headers",
                url=url,
                parameter="-",
                payload="-",
                evidence="Missing: " + ", ".join(missing),
            )
        )


async def _check_auth_bypass(url: str, authed_resp: httpx.Response, state: ScanState):
    """Re-request the same URL with NO session attached; flag if still accessible."""
    try:
        async with httpx.AsyncClient(
            timeout=REQUEST_TIMEOUT, follow_redirects=True, verify=False
        ) as anon_client:
            anon_resp = await anon_client.get(url)
    except Exception:
        return

    if anon_resp.status_code == 200 and len(anon_resp.content) > 50:
        lowered = anon_resp.text.lower()
        looks_like_login_redirect = any(
            marker in lowered
            for marker in ["log in", "sign in", "please authenticate", "session expired"]
        )
        if not looks_like_login_redirect:
            state.add_finding(
                Finding(
                    severity="High",
                    vuln_type="Authentication Bypass / Broken Access Control",
                    url=url,
                    parameter="-",
                    payload="(request sent without session)",
                    evidence=(
                        f"Protected page returned HTTP {anon_resp.status_code} "
                        f"({len(anon_resp.content)} bytes) even without an authenticated session."
                    ),
                )
            )
