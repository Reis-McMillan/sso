import logging

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlmodel import Session

from verys.database import get_session
from verys.models.external_provider import ExternalProvider
from verys.models.external_token import ExternalToken
from verys.models.scope import Scope
from verys.modules.encryption import encrypt_field

logger = logging.getLogger("verys.providers")

router = APIRouter(prefix="/providers", tags=["Providers"])


class ProviderCreateRequest(BaseModel):
    provider_id: str
    display_name: str
    client_id: str
    client_secret: str
    authorization_endpoint: str
    token_endpoint: str
    discovery_url: str
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
    if "admin" not in request.state.identity_roles:
        raise HTTPException(status_code=403, detail="Admin access required")

    existing = ExternalProvider.get_by_provider_id(session, body.provider_id)
    if existing:
        raise HTTPException(status_code=409, detail="Provider already exists")

    # Fetch OIDC discovery to get jwks_uri
    try:
        async with httpx.AsyncClient() as client:
            discovery_response = await client.get(body.discovery_url, headers={"Accept": "application/json"})
        if discovery_response.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to fetch OIDC discovery document")
        discovery = discovery_response.json()
        jwks_uri = discovery.get("jwks_uri")
        if not jwks_uri:
            raise HTTPException(status_code=400, detail="OIDC discovery document missing jwks_uri")
        userinfo_endpoint = discovery.get("userinfo_endpoint")
    except httpx.RequestError as e:
        logger.error(
            "Failed to fetch discovery URL %s: %s",
            body.discovery_url,
            e,
            exc_info=True
        )
        raise HTTPException(status_code=400, detail=f"Failed to reach discovery URL: {e}")

    provider = ExternalProvider(
        provider_id=body.provider_id,
        display_name=body.display_name,
        client_id=body.client_id,
        client_secret_encrypted=encrypt_field(body.client_secret),
        authorization_endpoint=body.authorization_endpoint,
        token_endpoint=body.token_endpoint,
        jwks_uri=jwks_uri,
        userinfo_endpoint=userinfo_endpoint,
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
        "jwks_uri": provider.jwks_uri,
        "userinfo_endpoint": provider.userinfo_endpoint,
        "scopes": provider.scopes,
        "enabled": provider.enabled,
        "created_at": provider.created_at.isoformat() if provider.created_at else None,
    }


@router.get("/")
async def list_providers(
    session: Session = Depends(get_session),
):
    providers = ExternalProvider.all(session)
    return [
        {
            "provider_id": p.provider_id,
            "display_name": p.display_name,
            "client_id": p.client_id,
            "authorization_endpoint": p.authorization_endpoint,
            "token_endpoint": p.token_endpoint,
            "jwks_uri": p.jwks_uri,
            "userinfo_endpoint": p.userinfo_endpoint,
            "scopes": p.scopes,
            "enabled": p.enabled,
            "created_at": p.created_at.isoformat() if p.created_at else None,
        }
        for p in providers
    ]


@router.get("/{provider_id}")
async def get_provider(
    provider_id: str,
    session: Session = Depends(get_session),
):
    provider = ExternalProvider.get_by_provider_id(session, provider_id)
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")

    return {
        "provider_id": provider.provider_id,
        "display_name": provider.display_name,
        "client_id": provider.client_id,
        "authorization_endpoint": provider.authorization_endpoint,
        "token_endpoint": provider.token_endpoint,
        "jwks_uri": provider.jwks_uri,
        "userinfo_endpoint": provider.userinfo_endpoint,
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
    if "admin" not in request.state.identity_roles:
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
    if "admin" not in request.state.identity_roles:
        raise HTTPException(status_code=403, detail="Admin access required")

    provider = ExternalProvider.get_by_provider_id(session, provider_id)
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")

    # Delete associated scope
    scope = Scope.get_by_provider(session, provider_id)
    if scope:
        session.delete(scope)

    # Delete associated external tokens for all users
    tokens = ExternalToken.get_all_for_provider(session, provider_id)
    for t in tokens:
        session.delete(t)

    session.delete(provider)
    session.commit()

    logger.info(
        "Provider deleted: %s (with %d tokens)",
        provider_id,
        len(tokens)
    )
    return {"detail": "Provider deleted"}
