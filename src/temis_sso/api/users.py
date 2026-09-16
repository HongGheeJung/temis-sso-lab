from typing import Annotated

import jwt
from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel

from temis_sso.persistence import UserRepository, session_scope
from temis_sso.tokens import codec

router = APIRouter(prefix="/users", tags=["users"])


class CurrentUser(BaseModel):
    user_id: str


def current_subject(authorization: Annotated[str | None, Header()] = None) -> str:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "bearer token required")
    try:
        return str(codec.verify_access(authorization.removeprefix("Bearer "))["sub"])
    except jwt.PyJWTError as error:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid access token") from error


@router.get("/me", response_model=CurrentUser)
async def me(user_id: Annotated[str, Depends(current_subject)]) -> CurrentUser:
    async with session_scope() as session:
        user = await UserRepository(session).by_id(user_id)
        if user is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
        if user.status != "active":
            raise HTTPException(status.HTTP_403_FORBIDDEN, "user is not active")
    return CurrentUser(user_id=user_id)
