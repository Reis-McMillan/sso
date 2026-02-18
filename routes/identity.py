import logging
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response, RedirectResponse
from sqlmodel import Session
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from urllib.parse import quote

from database import get_session
from models.identity import Identity
from config import config
from utils.cookie import encrypt_cookie
from utils.jwt import create_signed_jwt

logger = logging.getLogger("sso.identity")

router = APIRouter(prefix="/identity", tags=["Identity"])

@router.get("/", response_model=List[Identity])
async def get_all_identities(
    request: Request = None,
    session: Session = Depends(get_session)
):
    if "admin" not in request.state.auth_cache.roles:
        logger.warning("Forbidden: %s tried to list all identities", request.state.auth_cache.email)
        raise HTTPException(status_code=403, detail="Not authorized to perform this action.")

    return Identity.all(session)


@router.post("/", status_code=201)
async def create_identity(
    email: str,
    expires: Optional[datetime] = None,
    request: Request = None,
    session: Session = Depends(get_session),
):
    if "admin" not in request.state.auth_cache.roles:
        logger.warning("Forbidden: %s tried to create identity", request.state.auth_cache.email)
        raise HTTPException(status_code=403, detail="Not authorized to perform this action.")

    if not expires:
        expires = datetime.now(timezone.utc) + timedelta(seconds=config.AUTHENTICATION_TTL)

    key = Identity.make_auth_key()
    try:
        new_id = Identity.new(session, email, key, expires)
    except IntegrityError as e:
        logger.warning("Identity creation failed: duplicate email %s", email)
        raise HTTPException(status_code=400)
    url_safe_email = quote(new_id.email)
    logger.info("Identity created: %s by %s", email, request.state.auth_cache.email)
    return Response(status_code=201, headers={"Location": f"/identity/{url_safe_email}"})


@router.get("/cookie")
async def get_identity_cookie(
    request: Request = None,
    session: Session = Depends(get_session)
):
    target_identity = request.state.auth_cache.email

    this_identity = Identity.get(session, target_identity)
    if not this_identity:
        logger.warning("Cookie request: identity not found for %s", target_identity)
        raise HTTPException(status_code=404, detail="No Identity found.")

    value, iv = encrypt_cookie(this_identity.email, this_identity.auth_key)
    max_age = int(config.AUTHENTICATION_TTL)
    cookie_opts = {
        "httponly": True,
        "secure": True,
        "samesite": "strict",
        "max_age": max_age,
        "path": "/",
    }
    response = Response(status_code=200)
    response.set_cookie(key=config.ENCRYPT_COOKIE_NAME, value=value, **cookie_opts)
    response.set_cookie(key=f"{config.ENCRYPT_COOKIE_NAME}_iv", value=iv, **cookie_opts)
    logger.info("Cookie issued for %s", target_identity)
    return response


@router.get("/{email}")
async def get_identity(
    email: str,
    request: Request = None,
    session: Session = Depends(get_session)
):
    user_roles = getattr(request.state.auth_cache, "roles", [])
    r = Identity.get(session, email)

    # Admin Logic
    if "admin" in user_roles:
        if not r:
            logger.warning("Identity not found: %s (admin lookup)", email)
            raise HTTPException(status_code=404, detail="Identity not found")
        return r

    if (request.state.auth_cache.email != email):
        logger.warning("Forbidden: %s tried to access %s", request.state.auth_cache.email, email)
        raise HTTPException(status_code=403, detail="Not authorized to perform this action.")

    is_expired = r.expires < datetime.now(timezone.utc)
    if is_expired:
        url = request.url_for('handle_verification')
        url.include_query_params(email=request.state.auth_cache.email)
        return RedirectResponse(url)

    return create_signed_jwt(r.email, r.roles)


@router.put("/{email}", status_code=201)
async def update_identity(
    email: str,
    expires: datetime,
    request: Request = None,
    session: Session = Depends(get_session),
):
    if "admin" not in request.state.auth_cache.roles:
        logger.warning("Forbidden: %s tried to update identity %s", request.state.auth_cache.email, email)
        raise HTTPException(status_code=403, detail="Not authorized to perform this action.")

    key = Identity.make_auth_key()
    updated = Identity.update(session, email, key, expires)
    if not updated:
        logger.warning("Identity update failed: %s not found", email)
        raise HTTPException(status_code=404, detail="No Identity found.")
    url_safe_email = quote(email)
    logger.info("Identity updated: %s by %s", email, request.state.auth_cache.email)
    return Response(status_code=201, headers={"Location": f"/identity/{url_safe_email}"})


@router.delete("/{id}", status_code=204)
async def delete_identity(
    id: str,
    request: Request = None,
    session: Session = Depends(get_session)
):
    if "admin" not in request.state.auth_cache.roles:
        logger.warning("Forbidden: %s tried to delete identity %s", request.state.auth_cache.email, id)
        raise HTTPException(status_code=403, detail="Not authorized to perform this action.")

    r = Identity.close(session, id)
    if not r:
        logger.warning("Identity delete failed: %s not found", id)
        raise HTTPException(status_code=404, detail="Identity not found")
    logger.info("Identity deleted: %s by %s", id, request.state.auth_cache.email)
    return Response(status_code=204)


@router.post("/logout", status_code=201)
async def logout(
    request: Request,
    session: Session = Depends(get_session)
):
    logout_target = request.state.auth_cache.email
    new_key = Identity.make_auth_key()
    existing = Identity.get(session, logout_target)
    Identity.update(session, logout_target, new_key, existing.expires)
    logger.info("Logout: %s", logout_target)
    return Response(status_code=201)


@router.post("/{id}/logout", status_code=201)
async def logout_identity(
    id: str,
    request: Request,
    session: Session = Depends(get_session)
):
    if "admin" not in request.state.auth_cache.roles:
        logger.warning("Forbidden: %s tried to logout identity %s", request.state.auth_cache.email, id)
        raise HTTPException(status_code=403, detail="Not authorized to perform this action.")

    new_key = Identity.make_auth_key()
    existing = Identity.get(session, id)
    if not existing:
        logger.warning("Admin logout failed: identity %s not found", id)
        raise HTTPException(status_code=404)

    Identity.update(session, id, new_key, existing.expires)
    logger.info("Admin logout: %s by %s", id, request.state.auth_cache.email)
    return Response(status_code=201)
