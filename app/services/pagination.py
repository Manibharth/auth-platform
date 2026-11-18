"""Opaque cursor pagination on (created_at, id): stable under concurrent writes."""

from __future__ import annotations

import base64
import binascii
import json
import uuid
from datetime import datetime

from app.core.errors import ProblemError


def encode_cursor(created_at: datetime, row_id: uuid.UUID) -> str:
    raw = json.dumps({"c": created_at.isoformat(), "i": str(row_id)}, separators=(",", ":"))
    return base64.urlsafe_b64encode(raw.encode()).rstrip(b"=").decode()


def decode_cursor(cursor: str | None) -> tuple[datetime, uuid.UUID] | None:
    if not cursor:
        return None
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded.encode()))
        created_at = datetime.fromisoformat(data["c"])
        if created_at.tzinfo is None:
            raise ValueError("naive timestamp")
        return created_at, uuid.UUID(data["i"])
    except (
        ValueError,
        KeyError,
        TypeError,
        binascii.Error,
        json.JSONDecodeError,
        UnicodeDecodeError,
    ) as exc:
        raise ProblemError(
            400, "invalid_cursor", "Invalid cursor", "The pagination cursor is malformed"
        ) from exc
