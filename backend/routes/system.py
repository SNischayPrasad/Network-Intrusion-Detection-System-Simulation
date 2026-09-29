"""/api/health, /api/auth/whoami, /api/audit-log."""

from fastapi import APIRouter, Depends, Query, Request

from backend.services.audit import list_audit
from backend.utils.security import ADMIN_ROLES, Principal, authenticate, require_roles

router = APIRouter(prefix="/api", tags=["system"])


@router.get("/health")
def health(request: Request):
    """Unauthenticated liveness probe — reveals no sensitive data."""
    return {"status": "ok", "ml_enabled": request.app.state.ids.engine.ml_enabled}


@router.get("/auth/whoami")
def whoami(principal: Principal = Depends(authenticate)):
    return {"name": principal.name, "role": principal.role}


@router.get("/audit-log")
def audit_log(request: Request, limit: int = Query(200, ge=1, le=1000),
              target_id: str | None = Query(None, max_length=40),
              _: Principal = Depends(require_roles(*ADMIN_ROLES))):
    return {"items": list_audit(request.app.state.db, limit, target_id)}
