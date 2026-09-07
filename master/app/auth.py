import secrets

from itsdangerous import TimestampSigner

from . import config

_signer = TimestampSigner(config.SECRET_KEY)
SESSION_COOKIE = "afrog_session"
MAX_AGE = 60 * 60 * 24 * 7  # 7 days


def create_session() -> str:
    return _signer.sign("afrog-master").decode()


def verify_session(token: str) -> bool:
    if not token:
        return False
    try:
        _signer.unsign(token, max_age=MAX_AGE)
        return True
    except Exception:
        return False


def random_password() -> str:
    return secrets.token_hex(16)
