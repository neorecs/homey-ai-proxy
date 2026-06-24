import asyncio
import ipaddress
import logging
from typing import Any
from urllib.parse import urlparse

import httpx

from app.config import Settings


logger = logging.getLogger(__name__)


class HomeyClientError(RuntimeError):
    pass


class HomeyAuthError(HomeyClientError):
    pass


class HomeyRateLimitError(HomeyClientError):
    pass


class HomeyConfigurationError(HomeyClientError):
    pass


class BaseHomeyClient:
    async def status(self) -> dict[str, Any]:
        raise NotImplementedError

    async def get_devices(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    async def get_flows(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    async def start_flow(self, flow_name: str) -> dict[str, Any]:
        raise NotImplementedError


class MockHomeyClient(BaseHomeyClient):
    def __init__(self) -> None:
        self.started_flows: list[str] = []

    async def status(self) -> dict[str, Any]:
        return {"connected": True, "mode": "mock"}

    async def get_devices(self) -> list[dict[str, Any]]:
        return [
            {"id": "mock-light-1", "name": "Woonkamer lamp", "zone": "Woonkamer", "type": "light"},
            {"id": "mock-sensor-1", "name": "Presence sensor", "zone": "Hal", "type": "sensor"},
        ]

    async def get_flows(self) -> list[dict[str, Any]]:
        return [
            {"id": "flow-presence-test", "name": "AI - Presence test"},
            {"id": "flow-evening", "name": "AI - Avondmodus"},
            {"id": "flow-night", "name": "AI - Nachtmodus"},
            {"id": "flow-downstairs-off", "name": "AI - Alles uit beneden"},
            {"id": "flow-status", "name": "AI - Status huis"},
        ]

    async def start_flow(self, flow_name: str) -> dict[str, Any]:
        self.started_flows.append(flow_name)
        logger.info("Mock Homey flow started flow_name=%s", flow_name)
        return {"success": True, "flow_name": flow_name, "mode": "mock"}


class HttpHomeyClient(BaseHomeyClient):
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.base_url = settings.homey_base_url.rstrip("/")
        self._validate_local_transport()
        self.headers = {"Authorization": f"Bearer {settings.homey_token}"}

    def _validate_local_transport(self) -> None:
        if self.settings.homey_transport != "local":
            raise HomeyConfigurationError("Only HOMEY_TRANSPORT=local is supported")

        parsed = urlparse(self.base_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise HomeyConfigurationError("HOMEY_BASE_URL must be a valid local http(s) URL")

        hostname = parsed.hostname.lower()
        if hostname in {"api.athom.com", "my.homey.app"} or hostname.endswith(".athom.com"):
            raise HomeyConfigurationError("Cloud Homey endpoints are not allowed for runtime actions")

        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            if hostname.endswith(".local") or "." not in hostname:
                return
            raise HomeyConfigurationError("HOMEY_BASE_URL must point to a local/private Homey address")

        if not (address.is_private or address.is_loopback or address.is_link_local):
            raise HomeyConfigurationError("HOMEY_BASE_URL must point to a private/local IP address")

    @staticmethod
    def _error_detail(response: httpx.Response) -> str:
        try:
            data = response.json()
        except ValueError:
            text = response.text.strip()
            return text[:160] if text else response.reason_phrase
        if isinstance(data, dict):
            return str(data.get("error_description") or data.get("error") or response.reason_phrase)
        return response.reason_phrase

    async def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        if not self.settings.homey_token:
            raise HomeyAuthError("HOMEY_TOKEN is missing")
        if self.settings.homey_auth_mode == "oauth2_session":
            raise HomeyConfigurationError("HOMEY_AUTH_MODE=oauth2_session is not implemented yet")

        attempts = max(1, self.settings.homey_retry_attempts)
        delay = self.settings.homey_retry_base_delay_seconds
        last_error: Exception | None = None

        for attempt in range(1, attempts + 1):
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    response = await client.request(
                        method,
                        f"{self.base_url}{path}",
                        headers=self.headers,
                        **kwargs,
                    )
                if response.status_code in (401, 403):
                    raise HomeyAuthError(f"Homey token was rejected: {self._error_detail(response)}")
                if response.status_code == 429:
                    raise HomeyRateLimitError("Homey rate limit reached")
                response.raise_for_status()
                return response.json()
            except HomeyRateLimitError:
                raise
            except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError) as exc:
                last_error = exc
                if attempt == attempts:
                    break
                await asyncio.sleep(delay)
                delay *= 2

        raise HomeyClientError(f"Homey request failed after {attempts} attempts: {last_error}")

    async def status(self) -> dict[str, Any]:
        await self._request("GET", "/api/manager/system")
        return {"connected": True, "mode": "http"}

    async def get_devices(self) -> list[dict[str, Any]]:
        data = await self._request("GET", "/api/manager/devices/device")
        return list(data.values()) if isinstance(data, dict) else data

    async def get_flows(self) -> list[dict[str, Any]]:
        data = await self._request("GET", "/api/manager/flow/flow")
        return list(data.values()) if isinstance(data, dict) else data

    async def start_flow(self, flow_name: str) -> dict[str, Any]:
        flows = await self.get_flows()
        flow = next((item for item in flows if item.get("name") == flow_name), None)
        if not flow:
            raise HomeyClientError(f"Flow not found: {flow_name}")
        flow_id = flow.get("id")
        await self._request("POST", f"/api/manager/flow/flow/{flow_id}/trigger")
        return {"success": True, "flow_name": flow_name, "mode": "http"}


def create_homey_client(settings: Settings) -> BaseHomeyClient:
    if settings.homey_use_mock:
        return MockHomeyClient()
    return HttpHomeyClient(settings)
