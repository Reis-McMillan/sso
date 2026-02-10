from datetime import datetime, timezone
from fastapi import Request, HTTPException, Depends, Header
from sqlmodel import Session
from psycopg2.errors import UndefinedTable

from database import get_session
from models.identity import Identity
from utils.cookie import decrypt_cookie

async def authenticate_user(
    request: Request,
    x_auth_token: str = Header(None),
    x_init_vector: str = Header(None),
    session: Session = Depends(get_session)
) -> Identity:
    if not x_auth_token:
        raise HTTPException(status_code=401, detail="No Auth header set")

    if not x_init_vector:
        raise HTTPException(status_code=401, detail="No Init Vector header set")

    try:
        decrypted = decrypt_cookie(x_auth_token, x_init_vector)
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))
    
    try:    
        identity = Identity.get(session, decrypted["email"])
        
        if (not identity or 
            identity.auth_key != decrypted["auth_key"] or 
            datetime.now(timezone.utc) > identity.expires):
            
            raise HTTPException(status_code=401, detail="No valid authentication token found")

        request.state.auth_cache = identity
        
        return identity

    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))