"""Thin async HTTP client for a single peer, per
02_TECHNICAL_ARCHITECTURE.md section 6.1.

M1 is single-peer only (no fetch scheduler, no peer scoring -- that's M2),
so this client talks to exactly one base URL. Every method returns `None`
on a 404 (the caller decides what that means for the check in progress:
absence of a root document reads differently than absence of a
requested version) and raises NetworkError for transport failures or
unexpected statuses, so callers never have to distinguish "peer is down"
from "peer said no" via exception type inspection.
"""

from __future__ import annotations

import aiohttp

from .errors import NetworkError


class OriginClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self._session: aiohttp.ClientSession | None = None

    async def __aenter__(self) -> "OriginClient":
        self._session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, *exc_info) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None

    async def get_root(self, publisher: str, version: int) -> dict | None:
        return await self._get_json(f"/v1/{publisher}/meta/root/{version}")

    async def get_manifest(self, digest: str) -> dict | None:
        return await self._get_json(f"/v1/manifest/{digest}")

    async def get_chunk(self, digest: str, *, peer: str | None = None) -> bytes | None:
        return await self._get_bytes(f"/v1/chunk/{digest}")

    async def get_current(self, publisher: str, artifact: str, version: str) -> dict | None:
        return await self._get_json(f"/v1/{publisher}/current/{artifact}/{version}")

    async def _get_json(self, path: str) -> dict | None:
        try:
            async with self._session.get(self.base_url + path) as resp:
                if resp.status == 404:
                    return None
                if resp.status != 200:
                    raise NetworkError(f"unexpected status {resp.status} from {path}", peer=self.base_url)
                return await resp.json(content_type=None)
        except aiohttp.ClientError as e:
            raise NetworkError(f"network error fetching {path}: {e}", peer=self.base_url) from e

    async def _get_bytes(self, path: str) -> bytes | None:
        try:
            async with self._session.get(self.base_url + path) as resp:
                if resp.status == 404:
                    return None
                if resp.status != 200:
                    raise NetworkError(f"unexpected status {resp.status} from {path}", peer=self.base_url)
                return await resp.read()
        except aiohttp.ClientError as e:
            raise NetworkError(f"network error fetching {path}: {e}", peer=self.base_url) from e
