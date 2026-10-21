"""
Bayora Shield - JWT Authentication Module
Strict token creation and verification enforcing expiration, issuer, audience, and algorithm.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
import jwt
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from services.control_plane.config import settings

security_scheme = HTTPBearer(auto_error=False)


class SecurityContext(BaseModel):
    user_id: str
    tenant_id: str
    role: str
    email: Optional[str] = None


def create_access_token(
    user_id: str,
    tenant_id: str,
    role: str,
    email: Optional[str] = None,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Creates a signed JWT with standard claims (iss, aud, sub, tid, role, exp, iat).
    """
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    payload: Dict[str, Any] = {
        "sub": user_id,
        "tid": tenant_id,
        "role": role,
        "email": email or f"{user_id}@bayora.io",
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }

    encoded_jwt = jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
    return encoded_jwt


def decode_access_token(token: str) -> SecurityContext:
    """
    Validates signature, expiration, issuer, audience, and algorithm.
    Raises HTTPException(401) on any verification failure.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            issuer=settings.JWT_ISSUER,
            audience=settings.JWT_AUDIENCE,
            options={
                "require": ["exp", "iss", "aud", "sub", "tid", "role"],
                "verify_exp": True,
                "verify_iss": True,
                "verify_aud": True,
            },
        )
        user_id: str = payload.get("sub")
        tenant_id: str = payload.get("tid")
        role: str = payload.get("role")
        email: Optional[str] = payload.get("email")

        if not user_id or not tenant_id or not role:
            raise credentials_exception

        return SecurityContext(
            user_id=user_id,
            tenant_id=tenant_id,
            role=role,
            email=email,
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception:
        raise credentials_exception


async def get_current_user(
    auth_header: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
) -> SecurityContext:
    """FastAPI dependency to extract and validate the Bearer token."""
    if not auth_header or not auth_header.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return decode_access_token(auth_header.credentials)
