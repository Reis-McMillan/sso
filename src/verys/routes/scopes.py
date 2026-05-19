import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlmodel import Session

from verys.database import get_session
from verys.models.scope import Scope

logger = logging.getLogger("verys.scopes")

router = APIRouter(prefix="/scopes", tags=["Scopes"])


class ScopeCreateRequest(BaseModel):
    name: str
    description: str
    provider_id: str | None = None


class ScopeUpdateRequest(BaseModel):
    description: str | None = None
    provider_id: str | None = None


@router.post("/", status_code=201)
async def create_scope(
    request: Request,
    body: ScopeCreateRequest,
    session: Session = Depends(get_session),
):
    if "admin" not in request.state.identity_roles:
        raise HTTPException(status_code=403, detail="Admin access required")

    existing = Scope.get_by_name(session, body.name)
    if existing:
        raise HTTPException(status_code=409, detail="Scope already exists")

    scope = Scope(
        name=body.name,
        description=body.description,
        provider_id=body.provider_id,
    )
    session.add(scope)
    session.commit()
    session.refresh(scope)

    logger.info("Scope created: %s", scope.name)
    return {
        "name": scope.name,
        "description": scope.description,
        "provider_id": scope.provider_id,

        "created_at": scope.created_at.isoformat() if scope.created_at else None,
    }


@router.get("/")
async def list_scopes(
    request: Request,
    session: Session = Depends(get_session),
):
    if "admin" not in request.state.identity_roles:
        raise HTTPException(status_code=403, detail="Admin access required")

    scopes = Scope.all(session)
    return [
        {
            "name": s.name,
            "description": s.description,
            "provider_id": s.provider_id,

            "created_at": s.created_at.isoformat() if s.created_at else None,
        }
        for s in scopes
    ]


@router.get("/{name}")
async def get_scope(
    name: str,
    request: Request,
    session: Session = Depends(get_session),
):
    if "admin" not in request.state.identity_roles:
        raise HTTPException(status_code=403, detail="Admin access required")

    scope = Scope.get_by_name(session, name)
    if not scope:
        raise HTTPException(status_code=404, detail="Scope not found")

    return {
        "name": scope.name,
        "description": scope.description,
        "provider_id": scope.provider_id,

        "created_at": scope.created_at.isoformat() if scope.created_at else None,
    }


@router.put("/{name}")
async def update_scope(
    name: str,
    body: ScopeUpdateRequest,
    request: Request,
    session: Session = Depends(get_session),
):
    if "admin" not in request.state.identity_roles:
        raise HTTPException(status_code=403, detail="Admin access required")

    scope = Scope.get_by_name(session, name)
    if not scope:
        raise HTTPException(status_code=404, detail="Scope not found")

    if body.description is not None:
        scope.description = body.description
    if body.provider_id is not None:
        scope.provider_id = body.provider_id

    session.add(scope)
    session.commit()
    session.refresh(scope)

    logger.info("Scope updated: %s", scope.name)
    return {"detail": "Scope updated"}


@router.delete("/{name}")
async def delete_scope(
    name: str,
    request: Request,
    session: Session = Depends(get_session),
):
    if "admin" not in request.state.identity_roles:
        raise HTTPException(status_code=403, detail="Admin access required")

    if name in ("openid", "profile", "email"):
        raise HTTPException(status_code=400, detail="Cannot delete standard OIDC scopes")

    scope = Scope.get_by_name(session, name)
    if not scope:
        raise HTTPException(status_code=404, detail="Scope not found")

    session.delete(scope)
    session.commit()

    logger.info("Scope deleted: %s", name)
    return {"detail": "Scope deleted"}
