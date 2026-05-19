import logging
import secrets
import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlmodel import Session

from verys.config import config
from verys.database import get_session
from verys.models.oauth2_client import OAuthClient
from verys.models.scope import Scope
from verys.modules.client_auth import hash_client_secret

logger = logging.getLogger("verys.clients")

router = APIRouter(prefix="/clients", tags=["Clients"])


class ClientCreateRequest(BaseModel):
    client_name: str
    redirect_uris: list[str]
    allowed_scopes: list[str] = ["openid"]
    prm_uri: str | None = None
    grant_types: list[str] = ["authorization_code", "refresh_token"]
    token_endpoint_auth_method: str = "client_secret_basic"
    is_public: bool = False


class ClientUpdateRequest(BaseModel):
    client_name: str | None = None
    redirect_uris: list[str] | None = None
    allowed_scopes: list[str] | None = None
    prm_uri: str | None = None
    grant_types: list[str] | None = None
    token_endpoint_auth_method: str | None = None
    is_public: bool | None = None


async def _get_prm_uri(prm_uri: str, client_name: str, session: Session):
    async with httpx.AsyncClient() as client:
        response = await client.get(prm_uri)
        if response.status_code != 200:
            raise HTTPException(
                status_code=400,
                detail="Failed to retrieve OAuth metadata for client."
            )
        
        result: dict = response.json()
        if not config.ISSUER in result.get('authorization_servers', []):
            raise HTTPException(
                status_code=400,
                detail=f"Client must list {config.ISSUER} as authorization server."
            )
        
        if result.get('resource_name') != client_name:
            raise HTTPException(
                status_code=400,
                detail="Client name must match OAuth resource name."
            )
        
        required_scopes = result.get('scopes_supported', [])
        for s in required_scopes:
            if not Scope.get_by_name(session, s):
                raise HTTPException(status_code=400, detail=f"Unknown scope '{s}'")
        return required_scopes


@router.post("/", status_code=201)
async def create_client(
    request: Request,
    body: ClientCreateRequest,
    session: Session = Depends(get_session),
):
    if "admin" not in request.state.identity_roles:
        raise HTTPException(status_code=403, detail="Admin access required")

    # Validate scopes exist in the database
    for s in body.allowed_scopes:
        if not Scope.get_by_name(session, s):
            raise HTTPException(status_code=400, detail=f"Unknown scope '{s}'")

    required_scopes = []
    if body.prm_uri:
        required_scopes = await _get_prm_uri(body.prm_uri, body.client_name, session)

    # Generate client credentials
    plain_secret = secrets.token_urlsafe(48) if not body.is_public else None

    client = OAuthClient(
        client_name=body.client_name,
        redirect_uris=body.redirect_uris,
        allowed_scopes=body.allowed_scopes,
        prm_uri=body.prm_uri,
        required_scopes=required_scopes,
        grant_types=body.grant_types,
        token_endpoint_auth_method=body.token_endpoint_auth_method,
        is_public=body.is_public,
        client_secret_hash=hash_client_secret(plain_secret) if plain_secret else None,
        owner_email=request.state.identity.email,
    )
    session.add(client)
    session.commit()
    session.refresh(client)

    logger.info("Client created: %s (%s)", client.client_id, client.client_name)

    response = {
        "client_id": client.client_id,
        "client_name": client.client_name,
        "redirect_uris": client.redirect_uris,
        "allowed_scopes": client.allowed_scopes,
        "grant_types": client.grant_types,
        "token_endpoint_auth_method": client.token_endpoint_auth_method,
        "is_public": client.is_public,
    }
    if plain_secret:
        response["client_secret"] = plain_secret
    return response


@router.get("/")
async def list_clients(
    request: Request,
    session: Session = Depends(get_session),
):
    if "admin" not in request.state.identity_roles:
        raise HTTPException(status_code=403, detail="Admin access required")

    clients = OAuthClient.all(session)
    return [
        {
            "client_id": c.client_id,
            "client_name": c.client_name,
            "redirect_uris": c.redirect_uris,
            "allowed_scopes": c.allowed_scopes,
            "required_scopes": c.required_scopes,
            "is_public": c.is_public,
            "created_at": c.created_at.isoformat() if c.created_at else None,
        }
        for c in clients
    ]


@router.get("/{client_id}")
async def get_client(
    client_id: str,
    request: Request,
    session: Session = Depends(get_session),
):
    if "admin" not in request.state.identity_roles:
        raise HTTPException(status_code=403, detail="Admin access required")

    client = OAuthClient.get_by_client_id(session, client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    return {
        "client_id": client.client_id,
        "client_name": client.client_name,
        "redirect_uris": client.redirect_uris,
        "allowed_scopes": client.allowed_scopes,
        "required_scopes": client.required_scopes,
        "grant_types": client.grant_types,
        "token_endpoint_auth_method": client.token_endpoint_auth_method,
        "is_public": client.is_public,
        "created_at": client.created_at.isoformat() if client.created_at else None,
        "owner_email": client.owner_email,
    }


@router.put("/{client_id}")
async def update_client(
    client_id: str,
    body: ClientUpdateRequest,
    request: Request,
    session: Session = Depends(get_session),
):
    if "admin" not in request.state.identity_roles:
        raise HTTPException(status_code=403, detail="Admin access required")

    client = OAuthClient.get_by_client_id(session, client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    if body.client_name is not None:
        client.client_name = body.client_name
    if body.redirect_uris is not None:
        client.redirect_uris = body.redirect_uris
    if body.allowed_scopes is not None:
        for s in body.allowed_scopes:
            if not Scope.get_by_name(session, s):
                raise HTTPException(status_code=400, detail=f"Unknown scope '{s}'")
        client.allowed_scopes = body.allowed_scopes
    if body.prm_uri is not None:
        if body.client_name:
            client_name = body.client_name
        else:
            client_name = client.client_name
        required_scopes = await _get_prm_uri(body.prm_uri, client_name, session)
        client.prm_uri = body.prm_uri
        client.required_scopes = required_scopes
    if body.grant_types is not None:
        client.grant_types = body.grant_types
    if body.token_endpoint_auth_method is not None:
        client.token_endpoint_auth_method = body.token_endpoint_auth_method
    if body.is_public is not None:
        client.is_public = body.is_public

    session.add(client)
    session.commit()
    session.refresh(client)

    logger.info("Client updated: %s", client.client_id)
    return {"detail": "Client updated"}


@router.delete("/{client_id}")
async def delete_client(
    client_id: str,
    request: Request,
    session: Session = Depends(get_session),
):
    if "admin" not in request.state.identity_roles:
        raise HTTPException(status_code=403, detail="Admin access required")

    client = OAuthClient.get_by_client_id(session, client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    session.delete(client)
    session.commit()

    logger.info("Client deleted: %s", client_id)
    return {"detail": "Client deleted"}
