import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path

from . import config
from .db import init_db
from .redis_client import init_redis
from .routers import api, web

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("afrog-master")

BASE_DIR = Path(__file__).resolve().parent


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    init_redis()
    logger.info("Master started. password for web UI: %s", config.MASTER_PASSWORD)
    yield
    logger.info("Master stopped")


app = FastAPI(title="Afrog Distributed Master", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

app.include_router(web.router)
app.include_router(api.router)


@app.get("/")
async def root():
    return RedirectResponse(url="/results")
