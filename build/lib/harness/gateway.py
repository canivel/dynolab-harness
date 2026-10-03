"""Policy gateway for one exposed service. Runs inside its own sandbox container.

The agent's workstation reaches every service through one of these. Each connection is
allowed, denied or allowed-and-flagged by rule, and every attempt is appended to a JSON
log the harness reads as evidence. Standard library only, so any Python image can run it.

    python3 gateway.py /opt/gateway.json
"""
import asyncio
import json
import sys
import time

LOG = "/var/log/gateway.jsonl"


def log(event: dict) -> None:
    with open(LOG, "a") as f:
        f.write(json.dumps({"ts": time.time(), **event}) + "\n")


async def pipe(reader, writer, counter):
    try:
        while data := await reader.read(65536):
            counter[0] += len(data)
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        writer.close()


async def handle(cfg, client_reader, client_writer):
    peer = client_writer.get_extra_info("peername") or ("?", 0)
    base = {"host": cfg["host"], "port": cfg["port"], "client": peer[0], "action": cfg["action"],
            "tripwire": cfg.get("tripwire"), "severity": cfg.get("severity")}
    if cfg["action"] == "deny":
        log({**base, "result": "refused"})
        client_writer.close()
        return
    try:
        target_reader, target_writer = await asyncio.wait_for(
            asyncio.open_connection(cfg["target_host"], cfg["target_port"]), timeout=10)
    except (OSError, asyncio.TimeoutError) as e:
        log({**base, "result": "target_unreachable", "error": str(e)[:200]})
        client_writer.close()
        return
    sent, received = [0], [0]
    log({**base, "result": "connected"})
    await asyncio.gather(pipe(client_reader, target_writer, sent), pipe(target_reader, client_writer, received))
    log({**base, "result": "closed", "bytes_sent": sent[0], "bytes_received": received[0]})


async def main(path: str) -> None:
    """One gateway per hostname; one listener per rule (port) for that hostname."""
    with open(path) as f:
        rules = json.load(f)["rules"]
    servers = []
    for cfg in rules:
        servers.append(await asyncio.start_server(lambda r, w, cfg=cfg: handle(cfg, r, w), "0.0.0.0", cfg["port"]))
        log({"host": cfg["host"], "port": cfg["port"], "result": "listening", "action": cfg["action"]})
    await asyncio.gather(*(s.serve_forever() for s in servers))


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1]))
