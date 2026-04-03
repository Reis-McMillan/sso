import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlmodel import Session

from database import get_session
from models.external_provider import ExternalProvider
from models.external_token import ExternalToken
from models.scope import Scope
from utils.encryption import encrypt_field

logger = logging.getLogger("verys.providers")

router = APIRouter(prefix="/providers", tags=["Providers"])


class ProviderCreateRequest(BaseModel):
    provider_id: str
    display_name: str
    client_id: str
    client_secret: str
    authorization_endpoint: str
    token_endpoint: str
    scopes: list[str] = []


class ProviderUpdateRequest(BaseModel):
    display_name: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    authorization_endpoint: str | None = None
    token_endpoint: str | None = None
    enabled: bool | None = None
    scopes: list[str] | None = None


@router.post("/", status_code=201)
async def create_provider(
    request: Request,
    body: ProviderCreateRequest,
    session: Session = Depends(get_session),
):
    if "admin" not in request.state.identity.roles:
        raise HTTPException(status_code=403, detail="Admin access required")

    existing = ExternalProvider.get_by_provider_id(session, body.provider_id)
    if existing:
        raise HTTPException(status_code=409, detail="Provider already exists")

    provider = ExternalProvider(
        provider_id=body.provider_id,
        display_name=body.display_name,
        client_id=body.client_id,
        client_secret_encrypted=encrypt_field(body.client_secret),
        authorization_endpoint=body.authorization_endpoint,
        token_endpoint=body.token_endpoint,
        scopes=body.scopes,
    )
    session.add(provider)
    session.commit()
    session.refresh(provider)

    logger.info("Provider created: %s", provider.provider_id)
    return {
        "provider_id": provider.provider_id,
        "display_name": provider.display_name,
        "client_id": provider.client_id,
        "authorization_endpoint": provider.authorization_endpoint,
        "token_endpoint": provider.token_endpoint,
        "scopes": provider.scopes,
        "enabled": provider.enabled,
        "created_at": provider.created_at.isoformat() if provider.created_at else None,
    }


@router.get("/")
async def list_providers(
    request: Request,
    session: Session = Depends(get_session),
):
    if "admin" not in request.state.identity.roles:
        raise HTTPException(status_code=403, detail="Admin access required")

    providers = ExternalProvider.all(session)
    return [
        {
            "provider_id": p.provider_id,
            "display_name": p.display_name,
            "client_id": p.client_id,
            "authorization_endpoint": p.authorization_endpoint,
            "token_endpoint": p.token_endpoint,
            "scopes": p.scopes,
            "enabled": p.enabled,
            "created_at": p.created_at.isoformat() if p.created_at else None,
        }
        for p in providers
    ]


@router.get("/{provider_id}")
async def get_provider(
    provider_id: str,
    request: Request,
    session: Session = Depends(get_session),
):
    if "admin" not in request.state.identity.roles:
        raise HTTPException(status_code=403, detail="Admin access required")

    provider = ExternalProvider.get_by_provider_id(session, provider_id)
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")

    return {
        "provider_id": provider.provider_id,
        "display_name": provider.display_name,
        "client_id": provider.client_id,
        "authorization_endpoint": provider.authorization_endpoint,
        "token_endpoint": provider.token_endpoint,
        "scopes": provider.scopes,
        "enabled": provider.enabled,
        "created_at": provider.created_at.isoformat() if provider.created_at else None,
    }


@router.put("/{provider_id}")
async def update_provider(
    provider_id: str,
    body: ProviderUpdateRequest,
    request: Request,
    session: Session = Depends(get_session),
):
    if "admin" not in request.state.identity.roles:
        raise HTTPException(status_code=403, detail="Admin access required")

    provider = ExternalProvider.get_by_provider_id(session, provider_id)
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")

    if body.display_name is not None:
        provider.display_name = body.display_name
    if body.client_id is not None:
        provider.client_id = body.client_id
    if body.client_secret is not None:
        provider.client_secret_encrypted = encrypt_field(body.client_secret)
    if body.authorization_endpoint is not None:
        provider.authorization_endpoint = body.authorization_endpoint
    if body.token_endpoint is not None:
        provider.token_endpoint = body.token_endpoint
    if body.enabled is not None:
        provider.enabled = body.enabled
    if body.scopes is not None:
        provider.scopes = body.scopes

    session.add(provider)
    session.commit()
    session.refresh(provider)

    logger.info("Provider updated: %s", provider.provider_id)
    return {"detail": "Provider updated"}


@router.delete("/{provider_id}")
async def delete_provider(
    provider_id: str,
    request: Request,
    session: Session = Depends(get_session),
):
    if "admin" not in request.state.identity.roles:
        raise HTTPException(status_code=403, detail="Admin access required")

    provider = ExternalProvider.get_by_provider_id(session, provider_id)
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")

    # Delete associated scopes
    scopes = Scope.get_by_provider(session, provider_id)
    for s in scopes:
        session.delete(s)

    # Delete associated external tokens for all users
    tokens = ExternalToken.get_all_for_provider(session, provider_id)
    for t in tokens:
        session.delete(t)

    session.delete(provider)
    session.commit()

    logger.info("Provider deleted: %s (with %d scopes, %d tokens)", provider_id, len(scopes), len(tokens))
    return {"detail": "Provider deleted"}
