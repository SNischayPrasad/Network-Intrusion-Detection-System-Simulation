"""
FastAPI application factory.

Run (from the project root):
    uvicorn backend.app:app --reload --port 8000
Interactive API docs: http://127.0.0.1:8000/docs
"""

import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fastapi import FastAPI, Request  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
from fastapi.responses import JSONResponse  # noqa: E402

from backend.config import Settings  # noqa: E402
from backend.models.database import Database  # noqa: E402
from backend.routes import alerts, dashboard, flows, incidents, rules, system  # noqa: E402
from backend.services.ids_service import IDSService  # noqa: E402
from backend.utils.security import RateLimitMiddleware, SecurityHeadersMiddleware  # noqa: E402
from backend.utils.time_utils import now_iso  # noqa: E402
from ids.config import get_default_rules  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("ids.app")


def create_app(settings: Settings | None = None, engine=None) -> FastAPI:
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Startup: open the database, seed default rules, load baseline + ML model.
        db = Database(settings.db_path)
        db.init_schema()
        db.seed_rules(get_default_rules(), now_iso())
        app.state.db = db
        app.state.ids = IDSService(settings, db, engine=engine)
        settings.warn_if_insecure()
        yield

    app = FastAPI(
        title="Network IDS Simulation API",
        description="Defensive hybrid intrusion-detection simulation using synthetic flow data.",
        version="1.0.0",
        lifespan=lifespan,
    )
    app.state.settings = settings

    # Middleware (last added = outermost)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware, limit_per_minute=settings.rate_limit_per_minute)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,          # never "*" for an authenticated API
        allow_methods=["GET", "POST", "PUT"],
        allow_headers=["Content-Type", "X-API-Key"],
    )

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        # Log full details server-side; never leak stack traces to clients.
        log.exception("Unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse({"detail": "Internal server error"}, status_code=500)

    for module in (system, flows, alerts, incidents, dashboard, rules):
        app.include_router(module.router)
    return app


app = create_app()
