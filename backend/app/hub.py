"""Reparte cada ataque a todos los navegadores conectados por WebSocket."""

from __future__ import annotations

import asyncio
from collections import deque
from typing import Any

from fastapi import WebSocket

RECENT_SIZE = 200


class Hub:
    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()
        self.recent: deque[dict[str, Any]] = deque(maxlen=RECENT_SIZE)
        self.total = 0

    @property
    def client_count(self) -> int:
        return len(self._clients)

    async def connect(self, ws: WebSocket, source: str) -> None:
        await ws.accept()
        self._clients.add(ws)
        # Al conectar, el navegador recibe lo reciente para rellenar estadísticas y feed.
        await ws.send_json({"kind": "snapshot", "source": source, "events": list(self.recent)})

    def disconnect(self, ws: WebSocket) -> None:
        self._clients.discard(ws)

    async def publish(self, event: dict[str, Any]) -> None:
        self.total += 1
        self.recent.append(event)
        if not self._clients:
            return
        message = {"kind": "attack", "event": event}
        clients = list(self._clients)
        results = await asyncio.gather(
            *(ws.send_json(message) for ws in clients), return_exceptions=True
        )
        for ws, result in zip(clients, results):
            if isinstance(result, Exception):
                self.disconnect(ws)
