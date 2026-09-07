from typing import List

from pydantic import BaseModel, field_validator


class ScanOptions(BaseModel):
    search: str = ""
    severity: str = ""
    timeout: int = 0


class ScanCreate(BaseModel):
    name: str = ""
    urls: List[str]
    options: ScanOptions = ScanOptions()

    @field_validator("urls")
    @classmethod
    def normalize_urls(cls, v: List[str]) -> List[str]:
        out = []
        seen = set()
        for raw in v:
            for line in raw.splitlines():
                u = line.strip()
                if not u:
                    continue
                if "," in u:
                    u = u.split(",")[0].strip()
                if not u.startswith(("http://", "https://")):
                    u = "http://" + u
                if u not in seen:
                    seen.add(u)
                    out.append(u)
        if not out:
            raise ValueError("urls must not be empty")
        return out
