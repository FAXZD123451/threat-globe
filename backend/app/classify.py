"""Convierte eventos crudos de Cowrie en ataques que entiende el globo.

Cowrie registra cada sesión como una secuencia de eventos:
    session.connect → login.failed* → login.success? → command.input* → session.closed

El clasificador lleva un pequeño estado por sesión para distinguir, por ejemplo,
un escaneo (conecta y se va sin intentar login) de un ataque de fuerza bruta.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

# Comandos típicos de botnets tipo Mirai: buscan busybox o descargan binarios por arquitectura.
BOTNET_PATTERN = re.compile(
    r"busybox|/bin/busybox|\bECCHI\b|\bMIRAI\b|\.(?:x86|arm7?|mips|mpsl|sh4)\b|tftp\s",
    re.IGNORECASE,
)
DOWNLOAD_PATTERN = re.compile(r"\b(?:wget|curl)\s+\S+", re.IGNORECASE)

ATTACK_TYPES = ("scan", "ssh-brute", "intrusion", "command", "malware", "botnet")

# Límite de sesiones abiertas en memoria (Cowrie a veces no registra el cierre).
MAX_OPEN_SESSIONS = 5000


@dataclass
class _Session:
    tried_login: bool = False


@dataclass
class Classifier:
    _sessions: dict[str, _Session] = field(default_factory=dict)

    def classify(self, raw: dict[str, Any]) -> dict[str, Any] | None:
        """Devuelve un ataque {type, ip, timestamp, ...} o None si el evento no se dibuja."""
        event_id = raw.get("eventid", "")
        session_id = raw.get("session", "")
        ip = raw.get("src_ip")
        if not ip or not event_id.startswith("cowrie."):
            return None

        base = {
            "ip": ip,
            "session": session_id,
            "sensor": raw.get("sensor"),  # qué honeypot de la red recibió el ataque
            "timestamp": _parse_ts(raw.get("timestamp")),
        }

        if event_id == "cowrie.session.connect":
            self._open(session_id)
            return None

        if event_id in ("cowrie.login.failed", "cowrie.login.success"):
            self._open(session_id).tried_login = True
            credential = f"{raw.get('username', '')}:{raw.get('password', '')}"
            kind = "intrusion" if event_id == "cowrie.login.success" else "ssh-brute"
            return {**base, "type": kind, "credential": credential}

        if event_id == "cowrie.command.input":
            command = str(raw.get("input", ""))[:200]
            if BOTNET_PATTERN.search(command):
                kind = "botnet"
            elif DOWNLOAD_PATTERN.search(command):
                kind = "malware"
            else:
                kind = "command"
            return {**base, "type": kind, "command": command}

        if event_id == "cowrie.session.file_download":
            return {**base, "type": "malware", "command": f"descarga: {raw.get('url', '?')}"}

        if event_id == "cowrie.session.closed":
            session = self._sessions.pop(session_id, None)
            if session is not None and not session.tried_login:
                return {**base, "type": "scan"}
            return None

        return None

    def _open(self, session_id: str) -> _Session:
        if session_id not in self._sessions:
            if len(self._sessions) >= MAX_OPEN_SESSIONS:
                # Descarta la sesión más antigua (los dict mantienen el orden de inserción).
                self._sessions.pop(next(iter(self._sessions)))
            self._sessions[session_id] = _Session()
        return self._sessions[session_id]


def _parse_ts(value: Any) -> int:
    """Timestamp ISO de Cowrie → milisegundos epoch. Si falta, usa la hora actual."""
    if isinstance(value, str):
        try:
            return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000)
        except ValueError:
            pass
    return int(datetime.now().timestamp() * 1000)
