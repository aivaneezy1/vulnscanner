"""
auth.py
Handles two authentication modes for the scanner:

  B1. Form Login      -> Playwright headless Chromium drives a real login form,
                          then exports the resulting storage_state (cookies +
                          localStorage) so httpx can reuse the session.
  B2. Manual Session   -> The user pastes a raw Cookie header, a JSON cookie
                          export, or an `Authorization: Bearer <token>` line.
                          We parse that into a dict of cookies / headers.

Both modes produce a common `Session` object that scanner.py consumes.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from playwright.async_api import async_playwright, TimeoutError as PWTimeoutError


@dataclass
class Session:
    """Normalized session info usable by httpx for every subsequent request."""

    cookies: dict = field(default_factory=dict)      # name -> value
    headers: dict = field(default_factory=dict)      # e.g. {"Authorization": "Bearer ..."}
    origin: Optional[str] = None                     # scheme://host of the login page
    storage_state: Optional[dict] = None              # raw Playwright storage_state, if captured

    def is_empty(self) -> bool:
        return not self.cookies and not self.headers


class LoginError(Exception):
    pass


async def playwright_form_login(
    login_url: str,
    username: str,
    password: str,
    username_selector: Optional[str] = None,
    password_selector: Optional[str] = None,
    submit_selector: Optional[str] = None,
    extra_fields: Optional[dict] = None,
    timeout_ms: int = 20000,
) -> Session:
    """
    Drive a real browser through a login form and capture the resulting
    session (cookies + localStorage) via Playwright's storage_state().

    Raises LoginError with a human-readable message on any failure so the
    caller can surface it directly to the UI.
    """
    extra_fields = extra_fields or {}

    # Sensible default selectors, used only if the user didn't override them.
    default_user_selectors = [
        username_selector,
        "input[type=email]",
        "input[name=email]",
        "input[name=username]",
        "input[name=user]",
        "input[id=username]",
        "input[id=email]",
        "#username",
        "#email",
    ]
    default_pass_selectors = [
        password_selector,
        "input[type=password]",
        "input[name=password]",
        "#password",
    ]
    default_submit_selectors = [
        submit_selector,
        "button[type=submit]",
        "input[type=submit]",
        "button:has-text('Log in')",
        "button:has-text('Login')",
        "button:has-text('Sign in')",
    ]

    async with async_playwright() as pw:
        try:
            browser = await pw.chromium.launch(headless=True, args=["--no-sandbox"])
        except Exception as e:
            raise LoginError(f"Could not launch headless Chromium: {e}")

        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()

        try:
            try:
                await page.goto(login_url, wait_until="domcontentloaded", timeout=timeout_ms)
            except PWTimeoutError:
                raise LoginError(f"Timed out loading login page: {login_url}")
            except Exception as e:
                raise LoginError(f"Failed to load login page {login_url}: {e}")

            user_filled = await _fill_first_matching(page, default_user_selectors, username)
            if not user_filled:
                raise LoginError(
                    "Could not find a username/email field on the login page. "
                    "Try supplying a custom CSS selector."
                )

            pass_filled = await _fill_first_matching(page, default_pass_selectors, password)
            if not pass_filled:
                raise LoginError(
                    "Could not find a password field on the login page. "
                    "Try supplying a custom CSS selector."
                )

            # Any extra fields (CSRF tokens, hidden fields the user wants to set, etc.)
            for name, value in extra_fields.items():
                filled = await _fill_first_matching(
                    page,
                    [f"input[name='{name}']", f"#{name}", f"[name='{name}']"],
                    value,
                )
                # Non-fatal if an extra field can't be located.

            submitted = await _click_first_matching(page, default_submit_selectors)
            if not submitted:
                # Fall back to pressing Enter in the password field.
                try:
                    await page.keyboard.press("Enter")
                except Exception:
                    raise LoginError(
                        "Could not find a submit button and pressing Enter failed. "
                        "Try supplying a custom submit-button selector."
                    )

            try:
                await page.wait_for_load_state("networkidle", timeout=timeout_ms)
            except PWTimeoutError:
                pass  # Some apps keep background polling alive; not fatal.

            # Heuristic failure detection: still on a page with a visible password field
            # and some common error text usually means login failed.
            body_text = ""
            try:
                body_text = (await page.inner_text("body")).lower()
            except Exception:
                pass

            still_has_password_field = False
            try:
                still_has_password_field = await page.locator("input[type=password]").count() > 0
            except Exception:
                pass

            error_markers = [
                "invalid username",
                "invalid password",
                "incorrect password",
                "login failed",
                "authentication failed",
                "invalid credentials",
                "wrong password",
                "that didn't work",
            ]
            if any(marker in body_text for marker in error_markers):
                raise LoginError("Login page reported an authentication error.")

            if still_has_password_field and _looks_like_login_url(page.url, login_url):
                raise LoginError(
                    "Still appears to be on the login page after submitting. "
                    "Check the username/password or selectors."
                )

            storage_state = await context.storage_state()

            cookies = {c["name"]: c["value"] for c in storage_state.get("cookies", [])}
            if not cookies:
                raise LoginError("Login flow completed but no session cookies were set.")

            parsed = urlparse(page.url or login_url)
            origin = f"{parsed.scheme}://{parsed.netloc}"

            return Session(cookies=cookies, headers={}, origin=origin, storage_state=storage_state)

        finally:
            await context.close()
            await browser.close()


def _looks_like_login_url(current_url: str, login_url: str) -> bool:
    try:
        cur = urlparse(current_url)
        orig = urlparse(login_url)
        return cur.path == orig.path and cur.netloc == orig.netloc
    except Exception:
        return False


async def _fill_first_matching(page, selectors, value) -> bool:
    for sel in selectors:
        if not sel:
            continue
        try:
            locator = page.locator(sel).first
            if await locator.count() > 0:
                await locator.fill(value)
                return True
        except Exception:
            continue
    return False


async def _click_first_matching(page, selectors) -> bool:
    for sel in selectors:
        if not sel:
            continue
        try:
            locator = page.locator(sel).first
            if await locator.count() > 0:
                await locator.click()
                return True
        except Exception:
            continue
    return False


def parse_manual_session(raw_text: str) -> Session:
    """
    Accepts one of:
      - A raw 'Cookie: a=b; c=d' header or just 'a=b; c=d'
      - A JSON array of cookie objects (e.g. exported from browser devtools)
        like [{"name": "a", "value": "b", ...}, ...]
      - A JSON object mapping cookie name -> value
      - An 'Authorization: Bearer <token>' line (optionally combined with cookies)
    """
    raw_text = raw_text.strip()
    if not raw_text:
        raise LoginError("No session data provided.")

    cookies: dict = {}
    headers: dict = {}

    lines = [l.strip() for l in raw_text.splitlines() if l.strip()]

    # First, try whole-text JSON (cookie array or cookie map).
    try:
        data = json.loads(raw_text)
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and "name" in item and "value" in item:
                    cookies[item["name"]] = item["value"]
            if cookies:
                return Session(cookies=cookies, headers=headers)
        elif isinstance(data, dict):
            # Could be {"cookies": [...], "headers": {...}} or a flat name->value map
            if "cookies" in data or "headers" in data:
                for item in data.get("cookies", []):
                    if isinstance(item, dict) and "name" in item and "value" in item:
                        cookies[item["name"]] = item["value"]
                    elif isinstance(item, str) and "=" in item:
                        k, v = item.split("=", 1)
                        cookies[k.strip()] = v.strip()
                headers.update(data.get("headers", {}))
                return Session(cookies=cookies, headers=headers)
            else:
                # Flat map name -> value
                all_strings = all(isinstance(v, (str, int, float)) for v in data.values())
                if all_strings:
                    cookies = {k: str(v) for k, v in data.items()}
                    return Session(cookies=cookies, headers=headers)
    except json.JSONDecodeError:
        pass

    # Fall back to line-based parsing for headers like:
    #   Cookie: a=b; c=d
    #   Authorization: Bearer xyz
    #   a=b; c=d   (bare cookie string)
    for line in lines:
        m = re.match(r"(?i)^cookie:\s*(.+)$", line)
        if m:
            cookies.update(_parse_cookie_string(m.group(1)))
            continue
        m = re.match(r"(?i)^authorization:\s*(.+)$", line)
        if m:
            headers["Authorization"] = m.group(1).strip()
            continue
        m = re.match(r"(?i)^bearer\s+(.+)$", line)
        if m:
            headers["Authorization"] = f"Bearer {m.group(1).strip()}"
            continue
        if "=" in line and ";" in line:
            cookies.update(_parse_cookie_string(line))
            continue
        if re.match(r"^[\w\-\.]+=[^;]+$", line):
            k, v = line.split("=", 1)
            cookies[k.strip()] = v.strip()

    if not cookies and not headers:
        raise LoginError(
            "Could not parse the pasted session data. Provide a Cookie header, "
            "a JSON cookie export, or an Authorization: Bearer line."
        )

    return Session(cookies=cookies, headers=headers)


def _parse_cookie_string(s: str) -> dict:
    out = {}
    for part in s.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        out[k.strip()] = v.strip()
    return out
