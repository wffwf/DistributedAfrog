import os

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB = os.getenv("MONGO_DB", "afrog")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

MASTER_PASSWORD = os.getenv("MASTER_PASSWORD", "afrog@1234")
SECRET_KEY = os.getenv("SECRET_KEY", "afrog-master-secret-change-me")

HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8080"))

# redis keys
WORKER_KEY_PREFIX = "afrog:worker:"
WORKERS_SET = "afrog:workers"
HEARTBEAT_TTL = 15

# 结果列表分页大小(与 afrog-web 一致为 100)
PAGE_SIZE = int(os.getenv("PAGE_SIZE", "100"))
