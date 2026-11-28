from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError

from app.core.security import decode_token


oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/v1/auth/login"
)

async def get_current_user(
    token: str = Depends(oauth2_scheme)
):
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"}
    )

    try:
        payload = decode_token(token)

        if payload.get("type") != "access":
            raise credentials_error

        user_id = payload.get("sub")
        role = payload.get("role")

        if not user_id or role not in (
            "analyst", "admin", "auditor"
        ):
            raise credentials_error

        return {
            "id": user_id,
            "role": role
        }

    except JWTError:
        raise credentials_error


def require_roles(*allowed_roles: str):

    async def role_checker(
        current_user: dict = Depends(get_current_user)
    ):
        if current_user["role"] not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )

        return current_user

    return role_checker