"""Operational commands.

python -m app.cli seed [--demo-password ...]   roles, permissions, demo accounts
python -m app.cli generate-key [--out PATH] [--if-missing]
python -m app.cli purge-expired                 old idempotency keys
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.core.config import Settings
from app.core.security import PasswordHasher, generate_private_key_pem
from app.db.seed import ensure_demo_projects, ensure_roles, ensure_user
from app.db.session import create_engine, create_sessionmaker
from app.repositories.projects import IdempotencyRepository


async def _seed(args: argparse.Namespace) -> None:
    settings = Settings()
    engine = create_engine(settings)
    hasher = PasswordHasher.from_settings(settings)
    async with create_sessionmaker(engine)() as session:
        await ensure_roles(session)
        if args.admin_email and args.admin_password:
            await ensure_user(
                session, hasher, args.admin_email, args.admin_password, ["admin"], "Demo Admin"
            )
            print(f"admin ready: {args.admin_email}")
        if args.demo_email and args.demo_password:
            roles = ["user", "auditor"] if settings.demo_read_only else ["user"]
            demo = await ensure_user(
                session, hasher, args.demo_email, args.demo_password, roles, "Demo User"
            )
            await ensure_demo_projects(session, demo)
            print(f"demo user ready: {args.demo_email}")
        await session.commit()
    await engine.dispose()


async def _purge() -> None:
    settings = Settings()
    engine = create_engine(settings)
    async with create_sessionmaker(engine)() as session:
        n = await IdempotencyRepository(session).purge_all_expired(
            datetime.now(UTC), timedelta(hours=settings.idempotency_ttl_hours)
        )
        await session.commit()
    await engine.dispose()
    print(f"purged {n} idempotency keys")


def _generate_key(args: argparse.Namespace) -> None:
    pem = generate_private_key_pem()
    if not args.out:
        sys.stdout.write(pem)
        return
    out = Path(args.out)
    if args.if_missing and out.exists():
        print(f"{out} exists; keeping it")
        return
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(pem)
    out.chmod(0o600)
    print(f"wrote {out}")


def main() -> None:
    parser = argparse.ArgumentParser(prog="app.cli")
    sub = parser.add_subparsers(dest="cmd", required=True)
    seed = sub.add_parser("seed")
    seed.add_argument("--admin-email", default=os.environ.get("SEED_ADMIN_EMAIL"))
    seed.add_argument("--admin-password", default=os.environ.get("SEED_ADMIN_PASSWORD"))
    seed.add_argument("--demo-email", default=os.environ.get("SEED_DEMO_EMAIL"))
    seed.add_argument("--demo-password", default=os.environ.get("SEED_DEMO_PASSWORD"))
    key = sub.add_parser("generate-key")
    key.add_argument("--out")
    key.add_argument("--if-missing", action="store_true")
    sub.add_parser("purge-expired")
    args = parser.parse_args()
    if args.cmd == "seed":
        asyncio.run(_seed(args))
    elif args.cmd == "generate-key":
        _generate_key(args)
    else:
        asyncio.run(_purge())


if __name__ == "__main__":
    main()
