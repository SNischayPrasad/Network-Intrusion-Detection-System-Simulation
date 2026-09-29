"""
Authentication, authorisation, rate limiting and security headers.

Authentication  : every request (except /api/health) must send an API key in
                  the `X-API-Key` header. Keys are compared in constant time
                  (hmac.compare_digest) to avoid timing side-channels.
Authorisation   : role-based access control (RBAC) with least privilege:
                    sensor  -> may only SUBMIT flows
                    analyst -> may READ everything and work alerts (status/notes)
                    admin   -> analyst rights + edit detection rules + audit log
Rate limiting   : sliding 60-second window per client, returns HTTP 429.

Production note: API keys are a simple, teachable mechanism. A real SOC tool
would use SSO (OIDC/SAML) with MFA, short-lived tokens, and HTTPS everywhere.
"""

import hmac
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import APIKeyHeader
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


@dataclass(frozen=True)
class Principal:
    name: str
    role: str


def authenticate(request: Request, api_key: str | None = Depends(api_key_header)) -> Principal:
    settings = request.app.state.settings
    if not api_key:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing X-API-Key header",
                            headers={"WWW-Authenticate": "API-Key"})
    for role, expected in (("admin", settings.admin_key),
                           ("analyst", settings.analyst_key),
                           ("sensor", settings.sensor_key)):
        if expected and hmac.compare_digest(api_key.encode(), expected.encode()):
            return Principal(name=f"{role}-user", role=role)
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid API key",
                        headers={"WWW-Authenticate": "API-Key"})


def require_roles(*roles):
    """Dependency factory: `Depends(require_roles("analyst", "admin"))`."""
    def checker(principal: Principal = Depends(authenticate)) -> Principal:
        if principal.role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                f"Role '{principal.role}' is not allowed to perform this action")
        return principal
    return checker


READ_ROLES = ("analyst", "admin")
INGEST_ROLES = ("sensor", "admin")
ADMIN_ROLES = ("admin",)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """In-memory sliding-window limiter (per client IP + API key prefix)."""

    def __init__(self, app, limit_per_minute: int = 1200):
        super().__init__(app)
        self.limit = limit_per_minute
        self.hits = defaultdict(deque)
        self.lock = threading.Lock()

    async def dispatch(self, request, call_next):
        if self.limit > 0 and request.url.path.startswith("/api/"):
            client = request.client.host if request.client else "unknown"
            key = f"{client}:{(request.headers.get('x-api-key') or '')[:6]}"
            now = time.monotonic()
            with self.lock:
                window = self.hits[key]
                while window and now - window[0] > 60:
                    window.popleft()
                if len(window) >= self.limit:
                    retry = max(1, int(60 - (now - window[0])))
                    return JSONResponse({"detail": "Rate limit exceeded"}, status_code=429,
                                        headers={"Retry-After": str(retry)})
                window.append(now)
        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Defensive HTTP headers on every API response."""

    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Content-Security-Policy",
                                        "default-src 'none'; frame-ancestors 'none'")
        return response
