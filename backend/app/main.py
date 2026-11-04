"""Servidor de Threat Globe.

Cadena: log de Cowrie (JSON lines) → Classifier → GeoLocator → Hub → WebSocket /ws

Variables de entorno:
    THREAT_LOG        ruta al log de Cowrie            (por defecto data/cowrie.json)
    THREAT_GEOIP_DB   ruta a la base MMDB              (por defecto data/GeoLite2-City.mmdb)
    THREAT_SIMULATE   "1" escribe ataques simulados en el log, "0" solo lee  (por defecto 1)
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles

from .classify import Classifier
from .geo import GeoLocator, mask_ip
from .hub import Hub
from .simulator import run_simulator
from .tail import follow_jsonl

ROOT = Path(__file__).resolve().parents[2]
LOG_PATH = Path(os.environ.get("THREAT_LOG", ROOT / "data" / "cowrie.json"))
GEOIP_DB = Path(os.environ.get("THREAT_GEOIP_DB", ROOT / "data" / "GeoLite2-City.mmdb"))
SIMULATE = os.environ.get("THREAT_SIMULATE", "1") == "1"
FRONTEND = ROOT / "frontend"

log = logging.getLogger("threat-globe")


class Pipeline:
    """Convierte una línea cruda del log en un evento listo para el navegador."""

    def __init__(self, geo: GeoLocator, hub: Hub) -> None:
        self.classifier = Classifier()
        self.geo = geo
        self.hub = hub
        self._ids = itertools.count(1)

    async def process(self, raw: dict[str, Any]) -> dict[str, Any] | None:
        attack = self.classifier.classify(raw)
        if attack is None:
            return None
        where = self.geo.locate(attack["ip"])
        event = {
            "id": next(self._ids),
            "timestamp": attack["timestamp"],
            "ip": mask_ip(attack["ip"]),  # nunca se publica la IP completa
            "country": where.country,
            "country_code": where.country_code,
            "lat": where.lat,
            "lng": where.lng,
            "type": attack["type"],
            "sensor": attack["sensor"],
            "credential": attack.get("credential"),
            "command": attack.get("command"),
        }
        await self.hub.publish(event)
        return event


@asynccontextmanager
async def lifespan(app: FastAPI):
    geo = GeoLocator(GEOIP_DB)
    hub = Hub()
    pipeline = Pipeline(geo, hub)
    app.state.hub = hub
    app.state.pipeline = pipeline
    app.state.source = "simulator" if SIMULATE else "cowrie"
    app.state.geoip = geo.has_database

    async def consume() -> None:
        async for raw in follow_jsonl(LOG_PATH):
            try:
                await pipeline.process(raw)
            except Exception:  # un evento raro no debe tumbar el servidor
                log.exception("Error procesando evento")

    tasks = [asyncio.create_task(consume())]
    if SIMULATE:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        tasks.append(asyncio.create_task(run_simulator(LOG_PATH)))
    log.info("Leyendo %s | simulador=%s | geoip=%s", LOG_PATH, SIMULATE, geo.has_database)

    yield

    for task in tasks:
        task.cancel()
    for task in tasks:
        with contextlib.suppress(asyncio.CancelledError):
            await task
    geo.close()


app = FastAPI(title="Threat Globe", lifespan=lifespan)


@app.get("/api/health")
async def health() -> dict[str, Any]:
    hub: Hub = app.state.hub
    return {
        "status": "ok",
        "source": app.state.source,
        "geoip_database": app.state.geoip,
        "clients": hub.client_count,
        "events_total": hub.total,
    }


@app.websocket("/ws")
async def websocket(ws: WebSocket) -> None:
    hub: Hub = ws.app.state.hub
    await hub.connect(ws, ws.app.state.source)
    try:
        while True:
            await ws.receive_text()  # el navegador no envía nada; esto detecta el cierre
    except WebSocketDisconnect:
        pass
    finally:
        hub.disconnect(ws)


# El frontend se sirve desde el mismo servidor (va al final para no tapar /api ni /ws).
app.mount("/", StaticFiles(directory=FRONTEND, html=True), name="frontend")
