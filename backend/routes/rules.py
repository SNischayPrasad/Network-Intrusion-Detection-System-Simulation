"""
/api/rules — view (analyst) and tune (admin only) detection rules.
Changes take effect immediately for newly ingested flows.
"""

from fastapi import APIRouter, Depends, HTTPException, Path, Request, status

from backend.models.schemas import RuleUpdate
from backend.services import rule_service
from backend.utils.security import ADMIN_ROLES, READ_ROLES, Principal, require_roles

router = APIRouter(prefix="/api/rules", tags=["rules"])


@router.get("")
def list_rules(request: Request, _: Principal = Depends(require_roles(*READ_ROLES))):
    return {"items": request.app.state.db.load_rules()}


@router.put("/{rule_id}")
def update_rule(body: RuleUpdate, request: Request,
                rule_id: str = Path(pattern=r"^IDS-\d{3}$"),
                principal: Principal = Depends(require_roles(*ADMIN_ROLES))):
    try:
        updated = rule_service.update_rule(request.app.state.db, rule_id, body, principal)
    except rule_service.RuleValidationError as exc:
        raise HTTPException(422, str(exc))
    if updated is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found")
    request.app.state.ids.reload_rules()  # hot-reload into the running engine
    return updated
