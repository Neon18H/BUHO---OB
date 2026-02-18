import re
from typing import Any

SECRET_RE = re.compile(r'(?i)(authorization:|bearer\s+[A-Za-z0-9\-_\.]+|api[_-]?key\s*=\s*\S+|password\s*=\s*\S+|token\s*=\s*\S+)')


def redact_text(value: str) -> str:
    if not value:
        return value
    return SECRET_RE.sub('[REDACTED]', value)


def redact_payload(value: Any):
    if isinstance(value, dict):
        return {k: redact_payload(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_payload(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
