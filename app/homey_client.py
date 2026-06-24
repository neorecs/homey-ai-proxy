import asyncio
import base64
import ipaddress
import logging
import time
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


class HomeyOAuthSessionProvider:
    def __init__(self, settings: Settings, base_url: str) -> None:
        self.settings = settings
        self.base_url = base_url
        self._access_token = settings.homey_oauth_access_token
        self._access_expires_at = time.monotonic() + 300 if self._access_token else 0.0
        self._session_token = ""
        self._lock = asyncio.Lock()

    def _validate_refresh_settings(self) -> None:
        missing = [
            name
            for name, value in {
                "HOMEY_OAUTH_CLIENT_ID": self.settings.homey_oauth_client_id,
                "HOMEY_OAUTH_CLIENT_SECRET": self.settings.homey_oauth_client_secret,
                "HOMEY_OAUTH_REFRESH_TOKEN": self.settings.homey_oauth_refresh_token,
            }.items()
            if not value
        ]
        if missing:
            raise HomeyConfigurationError(f"Missing OAuth2 settings: {', '.join(missing)}")

    def _validate_any_token_source(self) -> None:
        if self._access_token:
            return
        self._validate_refresh_settings()

    @property
    def _basic_auth_header(self) -> str:
        raw = f"{self.settings.homey_oauth_client_id}:{self.settings.homey_oauth_client_secret}"
        encoded = base64.b64encode(raw.encode("utf-8")).decode("ascii")
        return f"Basic {encoded}"

    async def _refresh_access_token(self) -> str:
        self._validate_refresh_settings()
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.post(
                "https://api.athom.com/oauth2/token",
                headers={
                    "Authorization": self._basic_auth_header,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": self.settings.homey_oauth_refresh_token,
                },
            )
        if response.status_code in (401, 403):
            raise HomeyAuthError(f"Homey OAuth2 refresh failed: {HttpHomeyClient._error_detail(response)}")
        response.raise_for_status()
        data = response.json()
        self._access_token = data["access_token"]
        expires_in = int(data.get("expires_in") or 3600)
        self._access_expires_at = time.monotonic() + max(60, expires_in - 60)
        return self._access_token

    async def _get_access_token(self) -> str:
        self._validate_any_token_source()
        if self._access_token and time.monotonic() < self._access_expires_at:
            return self._access_token
        return await self._refresh_access_token()

    async def _create_delegation_token(self, access_token: str) -> str:
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.post(
                "https://api.athom.com/delegation/token?audience=homey",
                headers={"Authorization": f"Bearer {access_token}"},
            )
        if response.status_code in (401, 403):
            raise HomeyAuthError(f"Homey delegation token failed: {HttpHomeyClient._error_detail(response)}")
        response.raise_for_status()
        token = response.json()
        if not isinstance(token, str) or not token:
            raise HomeyAuthError("Homey delegation token response was invalid")
        return token

    async def _create_local_session_token(self, delegation_token: str) -> str:
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.post(
                f"{self.base_url}/api/manager/users/login",
                json={"token": delegation_token},
            )
        if response.status_code in (401, 403):
            raise HomeyAuthError(f"Homey local session login failed: {HttpHomeyClient._error_detail(response)}")
        response.raise_for_status()
        token = response.json()
        if not isinstance(token, str) or not token:
            raise HomeyAuthError("Homey local session response was invalid")
        return token

    async def get_session_token(self, force_refresh: bool = False) -> str:
        async with self._lock:
            if self._session_token and not force_refresh:
                return self._session_token
            access_token = await self._get_access_token()
            delegation_token = await self._create_delegation_token(access_token)
            self._session_token = await self._create_local_session_token(delegation_token)
            return self._session_token

    def clear_session(self) -> None:
        self._session_token = ""


class HttpHomeyClient(BaseHomeyClient):
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.base_url = settings.homey_base_url.rstrip("/")
        self._validate_local_transport()
        self._oauth_session_provider = (
            HomeyOAuthSessionProvider(settings, self.base_url)
            if settings.homey_auth_mode == "oauth2_session"
            else None
        )

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
        if self.settings.homey_auth_mode == "oauth2_session":
            token = await self._oauth_session_provider.get_session_token()
        elif self.settings.homey_token:
            token = self.settings.homey_token
        else:
            raise HomeyAuthError("HOMEY_TOKEN is missing")

        attempts = max(1, self.settings.homey_retry_attempts)
        delay = self.settings.homey_retry_base_delay_seconds
        last_error: Exception | None = None

        for attempt in range(1, attempts + 1):
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    response = await client.request(
                        method,
                        f"{self.base_url}{path}",
                        headers={"Authorization": f"Bearer {token}"},
                        **kwargs,
                    )
                if response.status_code in (401, 403):
                    if self._oauth_session_provider is not None and attempt == 1:
                        self._oauth_session_provider.clear_session()
                        token = await self._oauth_session_provider.get_session_token(force_refresh=True)
                        continue
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
