import asyncio
import json
import logging
import os
import shutil
import socket
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone

import redis.asyncio as aioredis
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ReturnDocument

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
)
logger = logging.getLogger("afrog-worker")

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB = os.getenv("MONGO_DB", "afrog")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

WORKER_ID = os.getenv("WORKER_ID") or f"{socket.gethostname()}-{uuid.uuid4().hex[:6]}"
AFROG_BIN = os.getenv("AFROG_BIN", "afrog")
HEARTBEAT_INTERVAL = float(os.getenv("HEARTBEAT_INTERVAL", "5"))
HEARTBEAT_TTL = float(os.getenv("HEARTBEAT_TTL", "15"))
POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "3"))
SCAN_TIMEOUT = float(os.getenv("SCAN_TIMEOUT", "1200"))
WORKER_KEY = f"afrog:worker:{WORKER_ID}"
WORKERS_SET = "afrog:workers"
EXTRA_ARGS = os.getenv("AFROG_EXTRA_ARGS", "-nc").split()


def _now():
    return datetime.now(timezone.utc)


def _now_str():
    return _now().strftime("%Y-%m-%d %H:%M:%S")


def _local_ip() -> str:
    try:
        return socket.gethostbyname(socket.gethostname()) or ""
    except Exception:
        return ""


async def heartbeat(redis, state):
    payload = {
        "hostname": socket.gethostname(),
        "ip": _local_ip(),
        "status": state["status"],
        "current_task": state["current_task"],
        "scan_count": state["scan_count"],
        "afrog_bin": AFROG_BIN,
        "last_seen": _now_str(),
    }
    await redis.set(WORKER_KEY, json.dumps(payload), ex=int(HEARTBEAT_TTL))
    await redis.sadd(WORKERS_SET, WORKER_ID)


async def claim_task(db):
    doc = await db.tasks.find_one_and_update(
        {"status": "pending"},
        {
            "$set": {
                "status": "running",
                "worker_id": WORKER_ID,
                "started_at": _now(),
            }
        },
        return_document=ReturnDocument.AFTER,
    )
    return doc


def run_afrog(url: str, options: dict):
    outfile = tempfile.NamedTemporaryFile(suffix=".json", delete=False).name
    cmd = [AFROG_BIN, "-t", url, "-json-all", outfile]
    cmd += EXTRA_ARGS
    search = (options or {}).get("search", "").strip()
    severity = (options or {}).get("severity", "").strip()
    if search:
        cmd += ["-s", search]
    if severity:
        cmd += ["-S", severity]
    logger.info("run: %s", " ".join(cmd))
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=SCAN_TIMEOUT,
        errors="replace",
    )
    logger.debug("afrog stdout: %s", proc.stdout[-2000:])
    logger.debug("afrog stderr: %s", proc.stderr[-2000:])

    items = []
    try:
        with open(outfile, "r", encoding="utf-8", errors="replace") as f:
            data = f.read().strip()
            if data:
                items = json.loads(data)
                if not isinstance(items, list):
                    items = [items]
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("parse afrog output failed: %s", e)
        items = []
    finally:
        try:
            os.unlink(outfile)
        except OSError:
            pass
    return proc.returncode, items


def parse_item(item: dict) -> dict:
    if not isinstance(item, dict):
        return {}
    # afrog v2.x 旧格式：target / id / info(severity,name,author,description,reference) / request / response / other
    # afrog v3.x 新格式：target / fulltarget / pocinfo(id,infoname,infoseg,infoauthor,infodescription,inforeference) / pocresult[].(request,response)
    entry = item.get("info") or {}
    if not isinstance(entry, dict):
        entry = {}
    pocinfo = item.get("pocinfo") or {}
    if not isinstance(pocinfo, dict):
        pocinfo = {}

    def pick(old_key, new_key, default=""):
        val = entry.get(old_key) or pocinfo.get(new_key)
        if val is None:
            val = item.get(old_key)
        return default if val is None else val

    severity = str(
        entry.get("severity")
        or pocinfo.get("infoseg")
        or item.get("severity")
        or "info"
    ).lower()
    if severity == "mideum":
        severity = "medium"

    refs = entry.get("reference") or pocinfo.get("inforeference") or []
    if isinstance(refs, str):
        refs = [refs]

    id_ = entry.get("id") or pocinfo.get("id") or item.get("id") or ""
    request = item.get("request") or ""
    response = item.get("response") or ""
    pocresult = item.get("pocresult") or []
    if isinstance(pocresult, list):
        reqs = [
            r.get("request", "")
            for r in pocresult
            if isinstance(r, dict) and r.get("request")
        ]
        resps = [
            r.get("response", "")
            for r in pocresult
            if isinstance(r, dict) and r.get("response")
        ]
        if not request and reqs:
            request = "\n\n---\n\n".join(reqs)
        if not response and resps:
            response = "\n\n---\n\n".join(resps)

    latency = 0
    other = item.get("other") or {}
    if isinstance(other, dict) and other.get("latency"):
        try:
            latency = int(float(other.get("latency")))
        except (TypeError, ValueError):
            latency = 0

    return {
        "target": item.get("target", ""),
        "fulltarget": item.get("fulltarget", item.get("target", "")),
        "id": id_,
        "name": pick("name", "infoname"),
        "author": pick("author", "infoauthor"),
        "severity": severity,
        "description": pick("description", "infodescription"),
        "reference": refs,
        "request": request,
        "response": response,
        "latency": latency,
    }


async def do_scan(db, redis, task):
    task_id = task["_id"]
    url = task["url"]
    options = task.get("options") or {}
    try:
        code, items = await asyncio.to_thread(run_afrog, url, options)
    except subprocess.TimeoutExpired:
        code, items = -1, []
        logger.warning("afrog timeout for %s", url)

    vuln_count = 0
    if items:
        docs = []
        for it in items:
            parsed = parse_item(it)
            if not parsed["name"] and not parsed["id"]:
                continue
            parsed.update(
                {
                    "task_id": task_id,
                    "scan_id": task.get("scan_id"),
                    "worker_id": WORKER_ID,
                    "created_at": _now(),
                }
            )
            docs.append(parsed)
        if docs:
            await db.results.insert_many(docs)
        vuln_count = len(docs)

    status = "done"
    message = f"afrog exit={code}, vulns={vuln_count}"
    await db.tasks.update_one(
        {"_id": task_id},
        {
            "$set": {
                "status": status,
                "vuln_count": vuln_count,
                "message": message,
                "finished_at": _now(),
            }
        },
    )
    logger.info("task %s done: %s vulns=%s", task_id, url, vuln_count)


async def main():
    client = AsyncIOMotorClient(MONGO_URI)
    db = client[MONGO_DB]
    redis = aioredis.from_url(REDIS_URL, decode_responses=True)
    state = {"status": "idle", "current_task": None, "scan_count": 0}

    logger.info("worker %s started, afrog=%s", WORKER_ID, AFROG_BIN)
    if shutil.which(AFROG_BIN) is None and not os.path.exists(AFROG_BIN):
        logger.warning(
            "afrog binary not found at %s; put the linux executable at host ./afrog-bin/afrog "
            "(mounted to %s) or run 'docker compose exec worker download-afrog'",
            AFROG_BIN, os.path.dirname(AFROG_BIN),
        )

    while True:
        try:
            await heartbeat(redis, state)
        except Exception as e:
            logger.error("heartbeat failed: %s", e)

        try:
            task = await claim_task(db)
            if task is None:
                state["status"] = "idle"
                state["current_task"] = None
                await asyncio.sleep(POLL_INTERVAL)
                continue

            state["status"] = "busy"
            state["current_task"] = task["url"]
            try:
                await do_scan(db, redis, task)
                state["scan_count"] += 1
            except Exception as e:
                logger.exception("scan failed for %s", task["url"])
                await db.tasks.update_one(
                    {"_id": task["_id"]},
                    {
                        "$set": {
                            "status": "failed",
                            "message": str(e)[:2000],
                            "finished_at": _now(),
                        }
                    },
                )
            state["status"] = "idle"
            state["current_task"] = None
        except Exception as e:
            logger.exception("worker loop error: %s", e)
            await asyncio.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    asyncio.run(main())
