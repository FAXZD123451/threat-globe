# 🌐 Threat Globe

Visualizador 3D de ciberataques en tiempo real. Una red de honeypots registra cada intento de intrusión; el backend lo clasifica, lo geolocaliza y lo envía por WebSocket a un globo 3D donde se dibuja como un arco desde el país de origen hasta el sensor atacado.

> **Estado:** Fase 2: backend completo con datos simulados en formato Cowrie.

## Cómo funciona

```
[Honeypots Cowrie] → log JSON → [Clasificador] → [GeoIP] → [Hub WebSocket] → [Globo 3D]
   (o el simulador)               tipo de ataque   país +     /ws             Globe.GL
                                                   coords
```

| Evento de Cowrie | Se muestra como |
|---|---|
| Conecta y se va sin intentar login | Escaneo |
| `cowrie.login.failed` | Fuerza bruta SSH |
| `cowrie.login.success` | Acceso concedido |
| `cowrie.command.input` | Comandos en shell / Descarga de malware (`wget`, `curl`) / Botnet (`busybox`, Mirai) |
| `cowrie.session.file_download` | Descarga de malware |

El simulador escribe exactamente el mismo formato que Cowrie, así que pasar a datos reales consiste solo en apuntar el backend al log del honeypot.

## Ejecutar en local

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate          # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --port 8090
```

Abrir http://localhost:8090

| Variable | Por defecto | Qué hace |
|---|---|---|
| `THREAT_LOG` | `data/cowrie.json` | Log de Cowrie a seguir |
| `THREAT_SIMULATE` | `1` | `1` genera ataques simulados en ese log; `0` solo lee |
| `THREAT_GEOIP_DB` | `data/GeoLite2-City.mmdb` | Base de geolocalización (GeoLite2 o DB-IP Lite) |

Sin backend (por ejemplo, abriendo `frontend/` en GitHub Pages), el globo cambia solo a simulación local.

### Tests

```bash
cd backend
pytest
```

## Funcionalidades

- Globo 3D con fronteras; al acercarte aparecen los nombres de los países en español.
- Al pasar el mouse sobre un país se ve cuántos ataques salieron de él.
- Red de 7 sensores (Frankfurt, Nueva York, São Paulo, Singapur, Sídney, Johannesburgo, Tokio).
- Panel en vivo: total, ataques por minuto, tipos, países, sensores más atacados y credenciales más probadas.

## Roadmap

- [x] Fase 1: globo 3D con ataques simulados y panel de estadísticas
- [x] Fase 2: backend FastAPI, clasificador de eventos Cowrie, GeoIP y WebSocket
- [ ] Fase 3: honeypot real (Cowrie en Docker, en un VPS aislado)
- [ ] Fase 4: filtros, historial y resumen diario automático
- [ ] Fase 5: despliegue con demo pública

## Ética y privacidad

- Los honeypots solo **reciben** conexiones; no atacan a nadie.
- El backend **nunca publica la IP completa**: oculta el último octeto (IPv4) o deja solo el /48 (IPv6).
- Las credenciales que se muestran son las que prueban los bots, no contraseñas de nadie.
- La simulación usa IPs de rangos de documentación (RFC 5737).

## Stack

Python · FastAPI · WebSockets · geoip2 · pytest · JavaScript · [Globe.GL](https://github.com/vasturiano/globe.gl) · Three.js
