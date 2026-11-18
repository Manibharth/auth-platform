"""Create verified load-test accounts directly in the target database.

DATABASE_URL=... LOAD_USER_COUNT=50 python load/seed_load_users.py
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.config import Settings
from app.core.security import PasswordHasher
from app.db.seed import ensure_demo_projects, ensure_user
from app.db.session import create_engine, create_sessionmaker


async def main() -> None:
    settings = Settings()
    prefix = os.environ.get("LOAD_USER_PREFIX", "load")
    password = os.environ.get("LOAD_PASSWORD", "load-test-passphrase-42")
    count = int(os.environ.get("LOAD_USER_COUNT", "50"))
    hasher = PasswordHasher.from_settings(settings)
    engine = create_engine(settings)
    async with create_sessionmaker(engine)() as session:
        for i in range(count):
            email = f"{prefix}-{i}@loadtest.example"
            user = await ensure_user(session, hasher, email, password, ["user"])
            await ensure_demo_projects(session, user)
        await session.commit()
    await engine.dispose()
    print(f"{count} load users ready")


if __name__ == "__main__":
    asyncio.run(main())
