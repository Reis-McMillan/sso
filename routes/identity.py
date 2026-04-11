import logging
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, ValidationError
from sqlmodel import Session
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from urllib.parse import quote

from database import get_session
from models.identity import Identity, Role
from config import config

logger = logging.getLogger("verys.identity")

router = APIRouter(prefix="/identity", tags=["Identity"])

@router.get("/", response_model=List[Identity])
async def get_all_identities(
    request: Request = None,
    session: Session = Depends(get_session)
):
    if "admin" not in request.state.identity.roles:
        logger.warning("Forbidden: %s tried to list all identities", request.state.identity.email)
        raise HTTPException(status_code=403, detail="Not authorized to perform this action.")

    return Identity.all(session)


@router.post("/", status_code=201)
async def create_identity(
    email: str,
    first_name: str = "",
    last_name: str = "",
    expires: Optional[datetime] = None,
    request: Request = None,
    session: Session = Depends(get_session),
):
    if "admin" not in request.state.identity.roles:
        logger.warning("Forbidden: %s tried to create identity", request.state.identity.email)
        raise HTTPException(status_code=403, detail="Not authorized to perform this action.")

    if not expires:
        expires = datetime.now(timezone.utc) + timedelta(seconds=config.AUTHENTICATION_TTL)

    key = Identity.make_auth_key()
    try:
        new_id = Identity.new(session, first_name, last_name, email, key, expires)
    except IntegrityError as e:
        logger.warning("Identity creation failed: duplicate email %s", email)
        raise HTTPException(status_code=400)
    except ValidationError as e:
        logger.warning("Identity creation failed: validation error for %s - %s", email, e)
        raise HTTPException(status_code=400, detail=str(e))
    url_safe_email = quote(new_id.email)
    logger.info("Identity created: %s by %s", email, request.state.identity.email)
    return Response(status_code=201, headers={"Location": f"/identity/{url_safe_email}"})


@router.get("/{email}")
async def get_identity(
    email: str,
    request: Request = None,
    session: Session = Depends(get_session)
):
    r = Identity.get(session, email)

    if "admin" not in request.state.identity.roles:
        logger.warning("Forbidden: %s tried to get identity %s", request.state.identity.email, email)
        raise HTTPException(status_code=403, detail="Not authorized to perform this action.")
    
    if not r:
        logger.warning("Identity not found: %s (admin lookup)", email)
        raise HTTPException(status_code=404, detail="Identity not found")
    return r


class IdentityUpdate(BaseModel):
    new_email: Optional[str] = None
    new_key: Optional[str] = None
    new_expires: Optional[datetime] = None
    new_roles: Optional[list[Role]] = None

@router.put("/{email}", status_code=201)
async def update_identity(
    email: str,
    update: IdentityUpdate,
    request: Request = None,
    session: Session = Depends(get_session),
):
    if "admin" not in request.state.identity.roles:
        logger.warning("Forbidden: %s tried to update identity %s", request.state.identity.email, email)
        raise HTTPException(status_code=403, detail="Not authorized to perform this action.")

    try:
        updated = Identity.update(
            session,
            email,
            new_email=update.new_email,
            new_key=update.new_key,
            new_expires=update.new_expires,
            new_roles=update.new_roles
        )
    except ValidationError as e:
        logger.warning("Identity update failed: validation error for %s - %s", email, e)
        raise HTTPException(status_code=400, detail=str(e))
    if not updated:
        logger.warning("Identity update failed: %s not found", email)
        raise HTTPException(status_code=404, detail="No Identity found.")
    url_safe_email = quote(email)
    logger.info("Identity updated: %s by %s", email, request.state.identity.email)
    return Response(status_code=201, headers={"Location": f"/identity/{url_safe_email}"})


@router.delete("/{email}", status_code=204)
async def delete_identity(
    email: str,
    request: Request = None,
    session: Session = Depends(get_session)
):
    if "admin" not in request.state.identity.roles:
        logger.warning("Forbidden: %s tried to delete identity %s", request.state.identity.email, email)
        raise HTTPException(status_code=403, detail="Not authorized to perform this action.")

    r = Identity.close(session, email)
    if not r:
        logger.warning("Identity delete failed: %s not found", email)
        raise HTTPException(status_code=404, detail="Identity not found")
    logger.info("Identity deleted: %s by %s", email, request.state.identity.email)
    return Response(status_code=204)


@router.post("/logout", status_code=201)
async def logout(
    request: Request,
    session: Session = Depends(get_session)
):
    logout_target = request.state.identity.email
    new_key = Identity.make_auth_key()
    existing = Identity.get(session, logout_target)
    Identity.update(session, logout_target, new_key=new_key, new_expires=existing.expires)
    logger.info("Logout: %s", logout_target)
    return Response(status_code=201)


@router.post("/{id}/logout", status_code=201)
async def logout_identity(
    id: str,
    request: Request,
    session: Session = Depends(get_session)
):
    if "admin" not in request.state.identity.roles:
        logger.warning("Forbidden: %s tried to logout identity %s", request.state.identity.email, id)
        raise HTTPException(status_code=403, detail="Not authorized to perform this action.")

    new_key = Identity.make_auth_key()
    existing = Identity.get(session, id)
    if not existing:
        logger.warning("Admin logout failed: identity %s not found", id)
        raise HTTPException(status_code=404)

    Identity.update(session, id, new_key=new_key, new_expires=existing.expires)
    logger.info("Admin logout: %s by %s", id, request.state.identity.email)
    return Response(status_code=201)
