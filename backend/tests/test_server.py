import json

from fastapi.testclient import TestClient

import app.main as main


def test_websocket_receives_snapshot_then_live_events(tmp_path, monkeypatch):
    log = tmp_path / "cowrie.json"
    monkeypatch.setattr(main, "LOG_PATH", log)
    monkeypatch.setattr(main, "SIMULATE", False)

    with TestClient(main.app) as client:
        assert client.get("/api/health").json()["source"] == "cowrie"

        with client.websocket_connect("/ws") as ws:
            snapshot = ws.receive_json()
            assert snapshot == {"kind": "snapshot", "source": "cowrie", "events": []}

            # Escribimos en el log como lo haría Cowrie y debe llegar al navegador.
            with log.open("a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "eventid": "cowrie.login.failed", "session": "x", "src_ip": "198.51.100.9",
                    "username": "root", "password": "123456",
                    "timestamp": "2026-11-04T12:00:00Z",
                }) + "\n")

            message = ws.receive_json()
            assert message["kind"] == "attack"
            assert message["event"]["type"] == "ssh-brute"
            assert message["event"]["ip"] == "198.51.100.x"


def test_frontend_is_served(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "LOG_PATH", tmp_path / "cowrie.json")
    monkeypatch.setattr(main, "SIMULATE", False)
    with TestClient(main.app) as client:
        response = client.get("/")
        assert response.status_code == 200
        assert "THREAT GLOBE" in response.text
