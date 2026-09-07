import redis.asyncio as aioredis

from . import config

_redis = None


def init_redis() -> None:
    global _redis
    _redis = aioredis.from_url(config.REDIS_URL, decode_responses=True)


def get_redis() -> aioredis.Redis:
    if _redis is None:
        init_redis()
    return _redis
