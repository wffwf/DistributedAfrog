from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .. import config
from ..auth import SESSION_COOKIE, create_session, verify_session
from ..db import get_db
from ..redis_client import get_redis

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))


def _auth(request: Request) -> None:
    if not verify_session(request.cookies.get(SESSION_COOKIE)):
        raise HTTPException(status_code=303, headers={"Location": "/login"})


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if verify_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse(url="/results")
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@router.post("/login")
async def login_submit(request: Request):
    form = await request.form()
    password = str(form.get("password", ""))
    if password == config.MASTER_PASSWORD:
        resp = RedirectResponse(url="/results", status_code=303)
        resp.set_cookie(SESSION_COOKIE, create_session(), httponly=True, max_age=86400 * 7)
        return resp
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "error": "密码错误，请重试。"},
    )


@router.get("/logout")
async def logout():
    resp = RedirectResponse(url="/login")
    resp.delete_cookie(SESSION_COOKIE)
    return resp


@router.get("/results", response_class=HTMLResponse)
async def results_page(
    request: Request,
    severity: str = "",
    keyword: str = "",
    scan_id: str = "",
    page: int = 1,
):
    _auth(request)
    db = get_db()
    page = max(1, page)
    page_size = config.PAGE_SIZE

    query: dict = {}
    if scan_id:
        query["scan_id"] = _object_id(scan_id)
    sevs = [s.strip().lower() for s in severity.split(",") if s.strip()]
    if sevs:
        query["severity"] = {"$in": sevs}
    kw = keyword.strip()
    if kw:
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
    results = []
    async for r in cursor:
        results.append(r)

    return templates.TemplateResponse(
        "results.html",
        {
            "request": request,
            "results": results,
            "total": total,
            "page": page,
            "page_size": page_size,
            "severity": severity,
            "keyword": kw,
            "scan_id": scan_id,
            "sevs": sevs,
            "page_count": max(1, -(-total // page_size)),
        },
    )


@router.get("/tasks", response_class=HTMLResponse)
async def tasks_page(request: Request):
    _auth(request)
    db = get_db()
    scans = []
    async for s in db.scans.find({}).sort("created_at", -1).limit(200):
        s["_id_str"] = str(s["_id"])
        scans.append(s)
    stats = {}
    pipe = [
        {
            "$group": {
                "_id": "$scan_id",
                "total": {"$sum": 1},
                "pending": {"$sum": {"$cond": [{"$eq": ["$status", "pending"]}, 1, 0]}},
                "running": {"$sum": {"$cond": [{"$eq": ["$status", "running"]}, 1, 0]}},
                "done": {"$sum": {"$cond": [{"$eq": ["$status", "done"]}, 1, 0]}},
                "failed": {"$sum": {"$cond": [{"$eq": ["$status", "failed"]}, 1, 0]}},
                "vulns": {"$sum": "$vuln_count"},
            }
        }
    ]
    async for row in db.tasks.aggregate(pipe):
        stats[row["_id"]] = row
    return templates.TemplateResponse(
        "tasks.html", {"request": request, "scans": scans, "stats": stats}
    )


@router.get("/tasks/new", response_class=HTMLResponse)
async def new_task_page(request: Request):
    _auth(request)
    return templates.TemplateResponse("new_task.html", {"request": request})


@router.get("/workers", response_class=HTMLResponse)
async def workers_page(request: Request):
    _auth(request)
    r = get_redis()
    workers = []
    async for k in r.scan_iter(f"{config.WORKER_KEY_PREFIX}*"):
        val = await r.get(k)
        if not val:
            continue
        import json

        try:
            w = json.loads(val)
        except Exception:
            continue
        w["worker_id"] = k.split(":", 2)[-1]
        workers.append(w)
    workers.sort(key=lambda x: x.get("worker_id", ""))
    return templates.TemplateResponse(
        "workers.html", {"request": request, "workers": workers}
    )


def _object_id(value: str):
    from bson import ObjectId

    try:
        return ObjectId(value)
    except Exception:
        return None
