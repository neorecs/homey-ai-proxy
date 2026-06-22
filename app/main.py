import logging
from datetime import UTC, datetime
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request
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


@app.middleware("http")
async def request_logging(request: Request, call_next):
    logger.info("Incoming request method=%s path=%s", request.method, request.url.path)
    response = await call_next(request)
    logger.info("Request completed method=%s path=%s status=%s", request.method, request.url.path, response.status_code)
    return response


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
