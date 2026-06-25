import logging
import secrets
import base64
import hashlib
import hmac
import time
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from app.cache import TTLCache
from app.config import AppConfig, Settings, get_app_config, get_settings
from app.homey_client import BaseHomeyClient, HomeyClientError, create_homey_client
from app.intent_router import IntentRouter
from app.logger import configure_logging
from app.rate_limiter import HomeyQueue, HomeyRateLimiter
from app.security import SecurityError, validate_flow_start


settings = get_settings()
configure_logging(settings)
logger = logging.getLogger(__name__)

app = FastAPI(title="Homey AI Proxy", version="0.1.0")
app_config = get_app_config()
homey_client = create_homey_client(settings)
homey_queue = HomeyQueue(HomeyRateLimiter(settings.homey_max_requests_per_minute))
devices_cache: TTLCache[list[dict[str, Any]]] = TTLCache(settings.cache_ttl_seconds)
flows_cache: TTLCache[list[dict[str, Any]]] = TTLCache(settings.cache_ttl_seconds)
recent_commands: dict[str, float] = {}
SECRET_PLACEHOLDERS = {
    "",
    "replace-with-your-homey-token",
    "replace-with-your-token",
    "changeme",
    "change-me",
    "todo",
}
PUBLIC_PATHS = {"/health", "/setup", "/homey/oauth/callback"}
OAUTH_STATE_TTL_SECONDS = 15 * 60


class FlowRequest(BaseModel):
    flow_name: str


class CommandRequest(BaseModel):
    command: str


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def get_client() -> BaseHomeyClient:
    return homey_client


def get_config() -> AppConfig:
    return app_config


def has_real_secret(value: str) -> bool:
    normalized = value.strip().lower()
    return normalized not in SECRET_PLACEHOLDERS and not normalized.startswith("replace-with-")


def proxy_auth_enabled(current_settings: Settings) -> bool:
    return has_real_secret(current_settings.proxy_api_key)


def oauth_client_configured(current_settings: Settings) -> bool:
    return all(
        [
            has_real_secret(current_settings.homey_oauth_client_id),
            has_real_secret(current_settings.homey_oauth_client_secret),
            bool(current_settings.homey_oauth_redirect_uri.strip()),
        ]
    )


def homey_auth_configured(current_settings: Settings) -> bool:
    if current_settings.homey_use_mock:
        return True
    if current_settings.homey_auth_mode == "static_token":
        return has_real_secret(current_settings.homey_token)
    if current_settings.homey_auth_mode == "oauth2_session":
        has_access_token = has_real_secret(current_settings.homey_oauth_access_token)
        has_refresh_flow = all(
            [
                has_real_secret(current_settings.homey_oauth_client_id),
                has_real_secret(current_settings.homey_oauth_client_secret),
                has_real_secret(current_settings.homey_oauth_refresh_token),
            ]
        )
        return has_access_token or has_refresh_flow
    return False


def homey_readiness_snapshot(current_settings: Settings, config: AppConfig) -> dict[str, Any]:
    auth_configured = homey_auth_configured(current_settings)
    caller_auth_configured = proxy_auth_enabled(current_settings)
    allowlist_configured = bool(config.allowed_flows)
    command_map_configured = bool(config.command_map)
    local_runtime_configured = current_settings.homey_transport == "local" and not current_settings.homey_use_mock
    ready_for_live_test = (
        local_runtime_configured
        and caller_auth_configured
        and auth_configured
        and allowlist_configured
        and command_map_configured
    )

    next_step = "Configure PROXY_API_KEY and Homey auth before switching HOMEY_USE_MOCK=false."
    if current_settings.homey_use_mock:
        if not caller_auth_configured:
            next_step = "Set PROXY_API_KEY before switching HOMEY_USE_MOCK=false."
        elif auth_configured:
            next_step = "Set HOMEY_USE_MOCK=false and run /homey/readiness?live=true."
    elif not caller_auth_configured:
        next_step = "Set PROXY_API_KEY before allowing live Homey calls."
    elif not auth_configured:
        next_step = "Configure Homey auth before testing live Homey calls."
    elif not allowlist_configured:
        next_step = "Add safe flows to config.yaml allowed_flows."
    elif not command_map_configured:
        next_step = "Add safe natural-language commands to config.yaml command_map."
    else:
        next_step = "Run /homey/readiness?live=true, then test POST /homey/command with test presence."

    return {
        "ready_for_live_test": ready_for_live_test,
        "mock_mode": current_settings.homey_use_mock,
        "homey_base_url": current_settings.homey_base_url,
        "homey_transport": current_settings.homey_transport,
        "homey_auth_mode": current_settings.homey_auth_mode,
        "proxy_auth_enabled": caller_auth_configured,
        "oauth_client_configured": oauth_client_configured(current_settings),
        "auth_configured": auth_configured,
        "allowlist_configured": allowlist_configured,
        "allowed_flow_count": len(config.allowed_flows),
        "command_map_configured": command_map_configured,
        "command_count": len(config.command_map),
        "next_step": next_step,
    }


@app.middleware("http")
async def request_logging(request: Request, call_next):
    logger.info("Incoming request method=%s path=%s", request.method, request.url.path)
    response = await call_next(request)
    logger.info("Request completed method=%s path=%s status=%s", request.method, request.url.path, response.status_code)
    return response


@app.middleware("http")
async def proxy_api_key_auth(request: Request, call_next):
    if request.url.path in PUBLIC_PATHS or not proxy_auth_enabled(settings):
        return await call_next(request)

    provided_key = request.headers.get("x-api-key", "")
    if not secrets.compare_digest(provided_key, settings.proxy_api_key):
        logger.warning("Proxy API key rejected method=%s path=%s", request.method, request.url.path)
        return JSONResponse(status_code=401, content={"detail": "Invalid or missing API key"})

    return await call_next(request)


def homey_oauth_basic_auth_header(current_settings: Settings) -> str:
    raw = f"{current_settings.homey_oauth_client_id}:{current_settings.homey_oauth_client_secret}"
    encoded = base64.b64encode(raw.encode("utf-8")).decode("ascii")
    return f"Basic {encoded}"


def safe_homey_error_detail(response: httpx.Response) -> str:
    try:
        data = response.json()
    except ValueError:
        text = response.text.strip()
        return text[:200] if text else response.reason_phrase
    if isinstance(data, dict):
        detail = data.get("error_description") or data.get("error") or response.reason_phrase
        return str(detail)[:200]
    return response.reason_phrase


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _base64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def oauth_state_secret(current_settings: Settings) -> str:
    if has_real_secret(current_settings.proxy_api_key):
        return current_settings.proxy_api_key
    return current_settings.homey_oauth_client_secret


def create_oauth_state(current_settings: Settings) -> str:
    payload = f"{int(time.time())}.{secrets.token_urlsafe(18)}"
    signature = hmac.new(
        oauth_state_secret(current_settings).encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return _base64url_encode(f"{payload}.{signature}".encode("utf-8"))


def validate_oauth_state(state: str, current_settings: Settings) -> bool:
    try:
        decoded = _base64url_decode(state).decode("utf-8")
        timestamp_text, nonce, provided_signature = decoded.split(".", 2)
        timestamp = int(timestamp_text)
    except (ValueError, UnicodeDecodeError):
        return False

    if not nonce or time.time() - timestamp > OAUTH_STATE_TTL_SECONDS:
        return False

    payload = f"{timestamp_text}.{nonce}"
    expected_signature = hmac.new(
        oauth_state_secret(current_settings).encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(provided_signature, expected_signature)


@app.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "timestamp": utc_now()}


@app.get("/setup", response_class=HTMLResponse)
async def setup_page() -> str:
    return """<!doctype html>
<html lang="nl">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Homey AI Proxy Setup</title>
  <style>
    :root { color-scheme: light dark; font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    body { margin: 0; padding: 24px; background: #101418; color: #f4f7fb; }
    main { max-width: 860px; margin: 0 auto; }
    h1 { font-size: 28px; margin: 0 0 16px; }
    label { display: block; margin: 18px 0 8px; font-weight: 650; }
    input { width: 100%; box-sizing: border-box; padding: 12px; border-radius: 6px; border: 1px solid #4a5563; background: #151b22; color: #f4f7fb; }
    .actions { display: flex; flex-wrap: wrap; gap: 10px; margin: 18px 0; }
    button, a.button { border: 0; border-radius: 6px; padding: 11px 14px; background: #2d6cdf; color: white; font-weight: 650; text-decoration: none; cursor: pointer; }
    button.secondary { background: #3b4652; }
    pre { white-space: pre-wrap; word-break: break-word; min-height: 180px; padding: 16px; border-radius: 6px; background: #06080a; border: 1px solid #26313b; }
    .hint { color: #aab7c4; line-height: 1.5; }
  </style>
</head>
<body>
<main>
  <h1>Homey AI Proxy Setup</h1>
  <p class="hint">Vul je PROXY_API_KEY in. De key blijft alleen in dit browserveld en wordt als X-API-Key header naar je eigen proxy gestuurd.</p>
  <label for="apiKey">PROXY_API_KEY</label>
  <input id="apiKey" type="password" autocomplete="off" placeholder="Plak je proxy key">
  <div class="actions">
    <button onclick="callProxy('/homey/readiness')">Readiness</button>
    <button onclick="callProxy('/homey/readiness?live=true')">Live Readiness</button>
    <button onclick="getAuthorizeUrl()">OAuth URL</button>
    <button class="secondary" onclick="clearOutput()">Wis output</button>
  </div>
  <pre id="output">Klaar.</pre>
</main>
<script>
const output = document.getElementById('output');
function key() {
  return document.getElementById('apiKey').value.trim();
}
function write(value) {
  output.textContent = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
}
function clearOutput() {
  write('Klaar.');
}
async function callProxy(path) {
  if (!key()) {
    write('Vul eerst je PROXY_API_KEY in.');
    return;
  }
  try {
    const response = await fetch(path, { headers: { 'X-API-Key': key() } });
    const text = await response.text();
    let body;
    try { body = JSON.parse(text); } catch { body = text; }
    write({ status: response.status, body });
  } catch (error) {
    write(String(error));
  }
}
async function getAuthorizeUrl() {
  if (!key()) {
    write('Vul eerst je PROXY_API_KEY in.');
    return;
  }
  try {
    const response = await fetch('/homey/oauth/authorize-url', { headers: { 'X-API-Key': key() } });
    const body = await response.json();
    if (!response.ok) {
      write({ status: response.status, body });
      return;
    }
    write({ status: response.status, authorization_url: body.authorization_url, next_step: 'Open de link hieronder in deze browser.' });
    const link = document.createElement('a');
    link.href = body.authorization_url;
    link.textContent = 'Open Homey toestemming';
    link.className = 'button';
    link.style.display = 'inline-block';
    link.style.marginTop = '12px';
    link.target = '_self';
    output.appendChild(document.createElement('br'));
    output.appendChild(link);
  } catch (error) {
    write(String(error));
  }
}
</script>
</body>
</html>"""


@app.get("/homey/oauth/authorize-url")
async def homey_oauth_authorize_url() -> dict[str, Any]:
    if not oauth_client_configured(settings):
        raise HTTPException(
            status_code=400,
            detail="Configure HOMEY_OAUTH_CLIENT_ID, HOMEY_OAUTH_CLIENT_SECRET and HOMEY_OAUTH_REDIRECT_URI first",
        )

    state = create_oauth_state(settings)
    query = urlencode(
        {
            "response_type": "code",
            "client_id": settings.homey_oauth_client_id,
            "redirect_uri": settings.homey_oauth_redirect_uri,
            "state": state,
        }
    )
    return {
        "authorization_url": f"https://api.athom.com/oauth2/authorise?{query}",
        "redirect_uri": settings.homey_oauth_redirect_uri,
        "state": state,
        "next_step": "Open authorization_url, approve Homey access, then let Homey redirect back to this proxy.",
    }


@app.get("/homey/oauth/callback")
async def homey_oauth_callback(code: str = "", state: str = "") -> dict[str, Any]:
    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing OAuth2 code or state")
    if not validate_oauth_state(state, settings):
        raise HTTPException(status_code=400, detail="Invalid or expired OAuth2 state")
    if not oauth_client_configured(settings):
        raise HTTPException(
            status_code=400,
            detail="Configure HOMEY_OAUTH_CLIENT_ID, HOMEY_OAUTH_CLIENT_SECRET and HOMEY_OAUTH_REDIRECT_URI first",
        )

    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.post(
            "https://api.athom.com/oauth2/token",
            headers={
                "Authorization": homey_oauth_basic_auth_header(settings),
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": settings.homey_oauth_redirect_uri,
            },
        )
    if response.status_code in (401, 403):
        raise HTTPException(status_code=502, detail=f"Homey OAuth2 code exchange was rejected: {safe_homey_error_detail(response)}")
    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=502, detail=f"Homey OAuth2 code exchange failed: {safe_homey_error_detail(response)}") from exc

    data = response.json()
    refresh_token = data.get("refresh_token", "")
    access_token = data.get("access_token", "")
    if not refresh_token and not access_token:
        raise HTTPException(status_code=502, detail="Homey OAuth2 response did not include usable tokens")

    return {
        "success": True,
        "homey_auth_mode": "oauth2_session",
        "env": {
            "HOMEY_AUTH_MODE": "oauth2_session",
            "HOMEY_OAUTH_REFRESH_TOKEN": refresh_token,
            "HOMEY_OAUTH_ACCESS_TOKEN": access_token,
        },
        "expires_in": data.get("expires_in"),
        "next_step": "Copy these values into Dockhand environment variables, then redeploy. Do not commit them to Git.",
    }


@app.get("/homey/status")
async def homey_status(client: BaseHomeyClient = Depends(get_client)) -> dict[str, Any]:
    try:
        status = await homey_queue.run(client.status)
    except HomeyClientError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {
        "homey": status,
        "timestamp": utc_now(),
        "cache": {
            "devices_cached": devices_cache.get() is not None,
            "flows_cached": flows_cache.get() is not None,
            "ttl_seconds": settings.cache_ttl_seconds,
        },
    }


@app.get("/homey/readiness")
async def homey_readiness(
    live: bool = False,
    client: BaseHomeyClient = Depends(get_client),
    config: AppConfig = Depends(get_config),
) -> dict[str, Any]:
    snapshot = homey_readiness_snapshot(settings, config)
    live_result: dict[str, Any] | None = None
    if live:
        try:
            live_status = await homey_queue.run(client.status)
            live_result = {"ok": True, "homey": live_status}
        except HomeyClientError as exc:
            live_result = {"ok": False, "error": str(exc)}
    return {"timestamp": utc_now(), **snapshot, "live": live_result}


def filter_items(
    items: list[dict[str, Any]],
    zone: str | None = None,
    type_: str | None = None,
    name: str | None = None,
) -> list[dict[str, Any]]:
    filtered = items
    if zone:
        filtered = [item for item in filtered if str(item.get("zone", "")).lower() == zone.lower()]
    if type_:
        filtered = [item for item in filtered if str(item.get("type", "")).lower() == type_.lower()]
    if name:
        filtered = [item for item in filtered if name.lower() in str(item.get("name", "")).lower()]
    return filtered


@app.get("/homey/devices")
async def homey_devices(
    refresh: bool = False,
    zone: str | None = None,
    type_: str | None = Query(default=None, alias="type"),
    name: str | None = None,
    client: BaseHomeyClient = Depends(get_client),
) -> dict[str, Any]:
    cached = None if refresh else devices_cache.get()
    if cached is None:
        try:
            cached = devices_cache.set(await homey_queue.run(client.get_devices))
        except HomeyClientError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {
        "source": cached.source,
        "age_seconds": round(cached.age_seconds, 3),
        "items": filter_items(cached.value, zone=zone, type_=type_, name=name),
    }


@app.get("/homey/flows")
async def homey_flows(
    refresh: bool = False,
    client: BaseHomeyClient = Depends(get_client),
) -> dict[str, Any]:
    cached = None if refresh else flows_cache.get()
    if cached is None:
        try:
            cached = flows_cache.set(await homey_queue.run(client.get_flows))
        except HomeyClientError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {"source": cached.source, "age_seconds": round(cached.age_seconds, 3), "items": cached.value}


async def start_allowed_flow(
    flow_name: str,
    client: BaseHomeyClient,
    config: AppConfig,
    intent: str = "flow_start",
) -> dict[str, Any]:
    try:
        validate_flow_start(flow_name, config)
        result = await homey_queue.run(lambda: client.start_flow(flow_name))
        logger.info("Homey action executed intent=%s flow_name=%s result=%s", intent, flow_name, result.get("success"))
        return result
    except SecurityError as exc:
        logger.warning("Homey action blocked intent=%s flow_name=%s error=%s", intent, flow_name, exc)
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except HomeyClientError as exc:
        logger.error("Homey action failed intent=%s flow_name=%s error=%s", intent, flow_name, exc)
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post("/homey/flows/start")
async def homey_flow_start(
    request: FlowRequest,
    client: BaseHomeyClient = Depends(get_client),
    config: AppConfig = Depends(get_config),
) -> dict[str, Any]:
    result = await start_allowed_flow(request.flow_name, client, config)
    return {"success": True, "flow_name": request.flow_name, "result": result, "timestamp": utc_now()}


@app.post("/homey/flows/test")
async def homey_flow_test(
    request: FlowRequest,
    client: BaseHomeyClient = Depends(get_client),
    config: AppConfig = Depends(get_config),
) -> dict[str, Any]:
    result = await start_allowed_flow(request.flow_name, client, config, intent="flow_test")
    return {"success": True, "flow_name": request.flow_name, "result": result, "timestamp": utc_now()}


@app.post("/homey/command")
async def homey_command(
    request: CommandRequest,
    client: BaseHomeyClient = Depends(get_client),
    config: AppConfig = Depends(get_config),
) -> dict[str, Any]:
    router = IntentRouter(config)
    try:
        intent = router.resolve(request.command)
    except SecurityError as exc:
        logger.warning("Command blocked command=%s error=%s", request.command, exc)
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    debounce_key = intent.flow_name
    now = datetime.now(UTC).timestamp()
    previous = recent_commands.get(debounce_key)
    if previous and now - previous < settings.command_debounce_seconds:
        logger.info("Command debounced intent=%s flow_name=%s", intent.name, intent.flow_name)
        return {
            "success": False,
            "debounced": True,
            "intent": intent.name,
            "flow_name": intent.flow_name,
            "timestamp": utc_now(),
        }

    recent_commands[debounce_key] = now
    result = await start_allowed_flow(intent.flow_name, client, config, intent=intent.name)
    return {
        "success": True,
        "intent": intent.name,
        "flow_name": intent.flow_name,
        "result": result,
        "timestamp": utc_now(),
        "openai_enabled": settings.openai_enabled,
    }
