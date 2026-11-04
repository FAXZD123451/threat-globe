"""Sigue un archivo JSON-lines como `tail -f`, tolerando que aún no exista o que rote."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

POLL_SECONDS = 0.25


async def follow_jsonl(path: Path, from_start: bool = False) -> AsyncIterator[dict[str, Any]]:
    handle = None
    position = 0
    try:
        while True:
            if handle is None:
                if not path.exists():
                    # Si el archivo se crea después de arrancar, todo su contenido es nuevo.
                    from_start = True
                    await asyncio.sleep(POLL_SECONDS)
                    continue
                handle = path.open("r", encoding="utf-8", errors="replace")
                if not from_start:
                    handle.seek(0, 2)  # empieza por el final: solo eventos nuevos
                position = handle.tell()
                from_start = True  # tras una rotación se lee el archivo nuevo completo

            line = handle.readline()
            if line.endswith("\n"):
                position = handle.tell()
                record = _parse(line)
                if record is not None:
                    yield record
                continue

            # Línea incompleta o fin de archivo: vuelve al inicio de la línea y espera.
            handle.seek(position)
            if not path.exists() or path.stat().st_size < position:
                handle.close()  # el archivo rotó o se truncó
                handle = None
            await asyncio.sleep(POLL_SECONDS)
    finally:
        if handle is not None:
            handle.close()


def _parse(line: str) -> dict[str, Any] | None:
    try:
        record = json.loads(line)
    except json.JSONDecodeError:
        return None
    return record if isinstance(record, dict) else None
