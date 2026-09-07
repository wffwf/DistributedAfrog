import json
from datetime import datetime, timezone
from typing import List, Optional

from bson import ObjectId
from fastapi import APIRouter, HTTPException, Query

from .. import config
from ..db import get_db
from ..models import ScanCreate
from ..redis_client import get_redis

router = APIRouter(prefix="/api")


def _now():
    return datetime.now(timezone.utc)


def _oid(value) -> ObjectId:
    try:
        return ObjectId(value)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid id")


@router.post("/tasks")
async def create_scan(payload: ScanCreate):
    db = get_db()
    name = payload.name.strip() or payload.urls[0][:60]
    scan = {
        "name": name,
        "status": "pending",
        "created_at": _now(),
        "updated_at": _now(),
    }
    res = await db.scans.insert_one(scan)
    scan_id = res.inserted_id

    tasks = [
        {
            "scan_id": scan_id,
            "url": u,
            "status": "pending",
            "worker_id": None,
            "options": payload.options.model_dump(),
            "vuln_count": 0,
            "message": "",
            "created_at": _now(),
        }
        for u in payload.urls
    ]
    if tasks:
        await db.tasks.insert_many(tasks)

    return {"scan_id": str(scan_id), "name": name, "task_count": len(tasks)}


async def _scan_stats():
    db = get_db()
    pipe = [
        {
            "$group": {
                "_id": "$scan_id",
                "total": {"$sum": 1},
                "pending": {
                    "$sum": {"$cond": [{"$eq": ["$status", "pending"]}, 1, 0]}
                },
                "running": {
                    "$sum": {"$cond": [{"$eq": ["$status", "running"]}, 1, 0]}
                },
                "done": {"$sum": {"$cond": [{"$eq": ["$status", "done"]}, 1, 0]}},
                "failed": {"$sum": {"$cond": [{"$eq": ["$status", "failed"]}, 1, 0]}},
                "vulns": {"$sum": "$vuln_count"},
            }
        },
    ]
    stats = {}
    async for row in db.tasks.aggregate(pipe):
        stats[row["_id"]] = row
    return stats


def _derive_status(st: dict) -> str:
    if st["done"] + st["failed"] == st["total"]:
        return "failed" if st["failed"] else "done"
    if st["running"]:
        return "running"
    return "pending"


@router.get("/tasks")
async def list_scans(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
):
    db = get_db()
    stats = await _scan_stats()
    total = await db.scans.count_documents({})
    cursor = db.scans.find({}).sort("created_at", -1).skip((page - 1) * page_size).limit(page_size)
    scans = []
    async for s in cursor:
        st = stats.get(s["_id"], {})
        scans.append(
            {
                "id": str(s["_id"]),
                "name": s.get("name", ""),
                "status": _derive_status(st),
                "total": st.get("total", 0),
                "done": st.get("done", 0),
                "running": st.get("running", 0),
                "failed": st.get("failed", 0),
                "pending": st.get("pending", 0),
                "vuln_count": st.get("vulns", 0),
                "created_at": s["created_at"].isoformat(),
            }
        )
    return {"total": total, "page": page, "page_size": page_size, "items": scans}


@router.get("/tasks/{scan_id}")
async def get_scan(scan_id: str, status: Optional[str] = None):
    db = get_db()
    oid = _oid(scan_id)
    scan = await db.scans.find_one({"_id": oid})
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")
    query: dict = {"scan_id": oid}
    if status:
        query["status"] = status
    items = []
    async for t in db.tasks.find(query).sort("created_at", 1):
        items.append(
            {
                "id": str(t["_id"]),
                "url": t["url"],
                "status": t["status"],
                "worker_id": t.get("worker_id"),
                "vuln_count": t.get("vuln_count", 0),
                "message": t.get("message", ""),
            }
        )
    return {"scan_id": scan_id, "name": scan.get("name"), "items": items}


@router.get("/results")
async def list_results(
    severity: str = Query("", description="逗号分隔: critical,high,medium,low,info"),
    keyword: str = Query(""),
    scan_id: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(config.PAGE_SIZE, ge=1, le=500),
):
    db = get_db()
    query: dict = {}
    if scan_id:
        query["scan_id"] = _oid(scan_id)
    if severity:
        sevs = [s.strip().lower() for s in severity.split(",") if s.strip()]
        if sevs:
            query["severity"] = {"$in": sevs}
    if keyword:
        kw = keyword.strip().lower()
        query["$or"] = [
            {"id": {"$regex": kw, "$options": "i"}},
            {"name": {"$regex": kw, "$options": "i"}},
            {"fulltarget": {"$regex": kw, "$options": "i"}},
        ]

    total = await db.results.count_documents(query)
    cursor = (
        db.results.find(query)
        .sort("created_at", -1)
        .skip((page - 1) * page_size)
        .limit(page_size)
    )
    items = []
    async for r in cursor:
        items.append(_serialize_result(r))
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "severity": severity,
        "keyword": keyword,
        "items": items,
    }


def _serialize_result(r: dict) -> dict:
    return {
        "id": str(r["_id"]),
        "task_id": str(r.get("task_id", "")),
        "target": r.get("target", ""),
        "fulltarget": r.get("fulltarget", ""),
        "poc_id": r.get("id", ""),
        "name": r.get("name", ""),
        "author": r.get("author", ""),
        "severity": r.get("severity", "").lower(),
        "description": r.get("description", ""),
        "reference": r.get("reference", []),
        "request": r.get("request", ""),
        "response": r.get("response", ""),
        "latency": r.get("latency", 0),
        "created_at": r.get("created_at", _now()).isoformat(),
    }


@router.get("/results/{result_id}")
async def get_result(result_id: str):
    db = get_db()
    r = await db.results.find_one({"_id": _oid(result_id)})
    if not r:
        raise HTTPException(status_code=404, detail="result not found")
    return _serialize_result(r)


@router.get("/workers")
async def list_workers():
    r = get_redis()
    keys = []
    async for k in r.scan_iter(f"{config.WORKER_KEY_PREFIX}*"):
        keys.append(k)
    workers = []
    for k in keys:
        val = await r.get(k)
        if not val:
            continue
        try:
            w = json.loads(val)
        except json.JSONDecodeError:
            continue
        w["worker_id"] = k.split(":", 2)[-1]
        w["online"] = True
        workers.append(w)
    workers.sort(key=lambda x: x.get("worker_id", ""))
    return {"total": len(workers), "items": workers}
