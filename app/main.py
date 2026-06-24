import logging
import secrets
from datetime import UTC, datetime
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
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
PUBLIC_PATHS = {"/health"}


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


@app.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "timestamp": utc_now()}


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
