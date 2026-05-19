from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlmodel import Session
from sqlalchemy.exc import IntegrityError
from pydantic import BaseModel, ValidationError
import logging

from verys.database import get_session
from verys.models.role import Role
from verys.models.identity import Identity
from verys.models.identity_role import IdentityRole

logger = logging.getLogger('verys.roles')

router = APIRouter(prefix="/roles", tags=["Roles"])


class RoleCreateBody(BaseModel):
    name: str


def _require_admin(request: Request, action: str) -> None:
    if "admin" not in request.state.identity_roles:
        logger.warning(
            "Forbidden: %s tried to %s", request.state.identity.email, action
        )
        raise HTTPException(
            status_code=403, detail="Not authorized to perform this action."
        )


@router.get('/')
async def list_roles(
    request: Request,
    session: Session = Depends(get_session),
):
    _require_admin(request, "list roles")
    return JSONResponse(
        status_code=200,
        content={"roles": [r.name for r in Role.all(session)]},
    )


@router.post('/')
async def create_role(
    request: Request,
    body: RoleCreateBody,
    session: Session = Depends(get_session),
):
    _require_admin(request, "create a role")

    try:
        Role.new(session, body.name)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except IntegrityError:
        session.rollback()
        raise HTTPException(
            status_code=409, detail=f"Role {body.name} already exists."
        )

    return JSONResponse(
        status_code=201,
        content={"message": f"Role {body.name} created successfully."},
        headers={"Location": f"/roles/{body.name}"},
    )


@router.get('/{role_name}')
async def get_role(
    role_name: str,
    request: Request,
    session: Session = Depends(get_session),
):
    _require_admin(request, "access role list")

    role = Role.get(session, role_name)
    if not role:
        raise HTTPException(
            status_code=404, detail=f"Role {role_name} does not exist."
        )
    identity_ids = IdentityRole.list_role_identities(session, role.id)
    identities = Identity.get_by_id(session, identity_ids) if identity_ids else []
    identity_emails = [i.email for i in identities]

    return JSONResponse(
        status_code=200,
        content={
            "message": "Successfully retrieved role and associated identities.",
            "identity_emails": identity_emails,
        },
    )


@router.delete('/{role_name}')
async def delete_role(
    role_name: str,
    request: Request,
    session: Session = Depends(get_session),
):
    _require_admin(request, "delete a role")

    deleted_role = Role.delete(session, role_name)
    if not deleted_role:
        raise HTTPException(
            status_code=404, detail=f"Role {role_name} does not exist."
        )

    return JSONResponse(
        status_code=200,
        content={"message": f"Successfully deleted role {role_name}."},
    )


@router.post('/{role_name}/identities/{email}')
async def assign_role(
    role_name: str,
    email: str,
    request: Request,
    session: Session = Depends(get_session),
):
    _require_admin(request, f"assign role {role_name} to {email}")

    role = Role.get(session, role_name)
    if not role:
        raise HTTPException(
            status_code=404, detail=f"Role {role_name} does not exist."
        )
    identity = Identity.get(session, email)
    if not identity:
        raise HTTPException(
            status_code=404, detail=f"Identity {email} does not exist."
        )

    try:
        IdentityRole.add_identity_role(session, identity.id, role.id)
    except IntegrityError:
        session.rollback()
        return JSONResponse(
            status_code=200,
            content={
                "message": f"Identity {email} already has role {role_name}."
            },
        )

    logger.info(
        "Role %s assigned to %s by %s",
        role_name, email, request.state.identity.email,
    )
    return JSONResponse(
        status_code=201,
        content={
            "message": f"Role {role_name} assigned to {email}."
        },
    )


@router.delete('/{role_name}/identities/{email}')
async def revoke_role(
    role_name: str,
    email: str,
    request: Request,
    session: Session = Depends(get_session),
):
    _require_admin(request, f"revoke role {role_name} from {email}")

    role = Role.get(session, role_name)
    if not role:
        raise HTTPException(
            status_code=404, detail=f"Role {role_name} does not exist."
        )
    identity = Identity.get(session, email)
    if not identity:
        raise HTTPException(
            status_code=404, detail=f"Identity {email} does not exist."
        )

    removed = IdentityRole.remove_identity_role(session, identity.id, role.id)
    if not removed:
        raise HTTPException(
            status_code=404,
            detail=f"Identity {email} does not have role {role_name}.",
        )

    logger.info(
        "Role %s revoked from %s by %s",
        role_name, email, request.state.identity.email,
    )
    return JSONResponse(
        status_code=200,
        content={"message": f"Role {role_name} revoked from {email}."},
    )
