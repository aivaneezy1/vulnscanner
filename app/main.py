from __future__ import annotations

import logging
import os
import uuid
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from app.auth import (
    LoginError,
    Session,
    parse_manual_session,
    playwright_form_login,
)
from app.scanner import ScanState, run_scan

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vulnscan")

app = FastAPI(title="Self-Hosted Auth-Aware Vulnerability Scanner")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "app", "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "app", "templates"))

SCANS: dict[str, ScanState] = {}


# --------------------------------------------------------------------------
# Request models
# --------------------------------------------------------------------------

class LoginTestRequest(BaseModel):
    login_url: str
    username: str
    password: str
    username_selector: Optional[str] = None
    password_selector: Optional[str] = None
    submit_selector: Optional[str] = None
    extra_fields: Optional[dict] = Field(default_factory=dict)


class ScanStartRequest(BaseModel):
    target_url: Optional[str] = ""
    mode: str  # "unauthenticated" | "authenticated"
    auth_mode: Optional[str] = "form"  # "form" | "manual"

    # Form login fields
    login_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    username_selector: Optional[str] = None
    password_selector: Optional[str] = None
    submit_selector: Optional[str] = None
    extra_fields: Optional[dict] = Field(default_factory=dict)

    # Manual session field
    manual_session: Optional[str] = None

    urls_to_scan: list[str] = Field(default_factory=list)
    also_crawl: bool = False


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------

@app.get("/")
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/login/test")
async def login_test(payload: LoginTestRequest):
    try:
        session = await playwright_form_login(
            login_url=payload.login_url,
            username=payload.username,
            password=payload.password,
            username_selector=payload.username_selector or None,
            password_selector=payload.password_selector or None,
            submit_selector=payload.submit_selector or None,
            extra_fields=payload.extra_fields or {},
        )
        cookie_count = len(session.cookies)
        return {
            "ok": True,
            "message": f"Login successful ✓ ({cookie_count} session cookie"
            f"{'s' if cookie_count != 1 else ''} captured)",
        }
    except LoginError as e:
        return {"ok": False, "message": str(e)}
    except Exception as e:
        logger.exception("Unexpected error during login test")
        return {"ok": False, "message": f"Unexpected error: {e}"}


@app.post("/scan/start")
async def scan_start(payload: ScanStartRequest):
    scan_id = str(uuid.uuid4())
    state = ScanState(scan_id=scan_id)
    SCANS[scan_id] = state

    import asyncio

    asyncio.create_task(_run_scan_task(state, payload))

    return {"scan_id": scan_id}


@app.get("/scan/{scan_id}/status")
async def scan_status(scan_id: str):
    state = SCANS.get(scan_id)
    if not state:
        return JSONResponse(status_code=404, content={"error": "scan not found"})
    return state.to_dict()


# --------------------------------------------------------------------------
# Background scan task
# --------------------------------------------------------------------------

async def _run_scan_task(state: ScanState, payload: ScanStartRequest):
    authenticated = payload.mode == "authenticated"
    session: Optional[Session] = None

    try:
        if authenticated:
            if payload.auth_mode == "manual":
                state.set_stage("Parsing manual session")
                try:
                    session = parse_manual_session(payload.manual_session or "")
                except LoginError as e:
                    state.add_error(str(e))
                    state.set_stage("Error")
                    state.finished = True
                    return
            else:
                state.set_stage("Logging in")
                if not payload.login_url or not payload.username or not payload.password:
                    state.add_error(
                        "Authenticated scan requires a login URL, username, and password "
                        "(or switch to Manual Session)."
                    )
                    state.set_stage("Error")
                    state.finished = True
                    return
                try:
                    session = await playwright_form_login(
                        login_url=payload.login_url,
                        username=payload.username,
                        password=payload.password,
                        username_selector=payload.username_selector or None,
                        password_selector=payload.password_selector or None,
                        submit_selector=payload.submit_selector or None,
                        extra_fields=payload.extra_fields or {},
                    )
                except LoginError as e:
                    state.add_error(f"Login failed: {e}")
                    state.set_stage("Error")
                    state.finished = True
                    return

        await run_scan(
            state=state,
            target_url=(payload.target_url or "").strip(),
            authenticated=authenticated,
            session=session,
            urls_to_scan=[u.strip() for u in payload.urls_to_scan if u.strip()],
            also_crawl=payload.also_crawl,
        )

    except Exception as e:
        logger.exception("Scan task crashed")
        state.add_error(f"Scan crashed: {e}")
        state.set_stage("Error")
        state.finished = True


@app.on_event("startup")
async def on_startup():
    port = os.environ.get("PORT", "8000")
    logger.info(f"Vulnerability scanner starting up, bound to 0.0.0.0:{port}")
