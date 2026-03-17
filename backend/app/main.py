import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.config import settings
from app.database import engine, async_session
from app.models import Base
import app.models.event  # noqa: F401 - register models

import app.models.api_key  # noqa: F401
import app.models.rule  # noqa: F401
import app.models.rule_version  # noqa: F401
import app.models.user  # noqa: F401
import app.models.otp_code  # noqa: F401
from app.routers import auth as auth_router
from app.routers import events as events_router
from app.routers import overview as overview_router
from app.routers import alerts as alerts_router

from app.routers import compliance as compliance_router
from app.routers import developers as developers_router
from app.routers import audit as audit_router
from app.routers import rules as rules_router
from app.routers import users as users_router
from app.services.rule_loader import load_rules_from_directory
from app.services.rule_service import upsert_builtin_rule, bump_version


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    rules_dir = os.path.join(os.path.dirname(__file__), "..", "..", "rules")
    if os.path.isdir(rules_dir):
        rule_defs = load_rules_from_directory(rules_dir)
        async with async_session() as db:
            for rule_data in rule_defs:
                await upsert_builtin_rule(db, rule_data)
            await bump_version(db)
            await db.commit()

    from app.services.user_service import bootstrap_admin

    if settings.admin_email:
        async with async_session() as db:
            admin = await bootstrap_admin(db, settings.admin_email)
            if admin:
                print(f"Bootstrap admin created: {admin.email}")

    yield
    await engine.dispose()


app = FastAPI(
    title="Tatu — DevSecOps Platform",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(auth_router.router)
app.include_router(events_router.router)
app.include_router(overview_router.router)
app.include_router(alerts_router.router)

app.include_router(compliance_router.router)
app.include_router(developers_router.router)
app.include_router(audit_router.router)
app.include_router(rules_router.sync_router)
app.include_router(rules_router.router)
app.include_router(users_router.router)


@app.get("/api/v1/health")
async def health_check():
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return {"status": "ok", "db": "connected"}
    except Exception:
        return {"status": "degraded", "db": "disconnected"}
