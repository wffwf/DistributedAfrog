from typing import Optional

from motor.motor_asyncio import AsyncIOMotorClient

from . import config

_client: Optional[AsyncIOMotorClient] = None
db = None


def init_db() -> None:
    global _client, db
    _client = AsyncIOMotorClient(config.MONGO_URI)
    db = _client[config.MONGO_DB]


def get_db():
    if db is None:
        init_db()
    return db
