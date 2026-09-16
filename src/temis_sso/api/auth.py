from typing import Annotated

from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select

from temis_sso.application.auth import (
    DuplicateEmailError,
    InvalidCredentialsError,
    InvalidOneTimeTokenError,
    VerificationRequiredError,
    authenticate,
    register,
    request_password_reset,
    reset_password,
    verify_email,
)
from temis_sso.config import settings
from temis_sso.persistence import User, UserRole, session_scope
from temis_sso.tokens import codec, issue_refresh, revoke_refresh, rotate_refresh

router = APIRouter(prefix="/auth", tags=["auth"])


class Credentials(BaseModel):
    email: str
    password: str = Field(min_length=12, max_length=128)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        if "@" not in value or len(value) > 320:
            raise ValueError("valid email required")
        return value


class Identity(BaseModel):
    user_id: str
    email: str


class TokenBundle(BaseModel):
    user_id: str
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenInput(BaseModel):
    token: str


class RefreshInput(BaseModel):
    refresh_token: str


class ResetRequest(BaseModel):
    email: str


class ResetConfirm(TokenInput):
    password: str = Field(min_length=12, max_length=128)


class StatusInput(BaseModel):
    user_id: str
    authz_version: int


class StatusResult(BaseModel):
    active: bool
    authz_version: int | None


async def issue_bundle(
    user_id: str, audience: str = "temis-lab", refresh_token: str | None = None
) -> TokenBundle:
    async with session_scope() as session:
        user = await session.get(User, user_id)
        if user is None or user.status != "active":
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "active user required")
        roles = list(
            await session.scalars(select(UserRole.role).where(UserRole.user_id == user_id))
        )
        scopes = ["profile:read", "reports:read"]
        if "admin" in roles:
            scopes.append("admin:write")
        refresh = refresh_token or await issue_refresh(session, user_id, audience)
        access = codec.issue_access(
            user_id,
            roles=[f"temis:{role}" for role in roles],
            audience=audience,
            scopes=scopes,
            authz_version=user.authz_version,
        )
    return TokenBundle(user_id=user_id, access_token=access, refresh_token=refresh)


@router.post("/status", response_model=StatusResult)
async def authorization_status(
    payload: StatusInput,
    service_key: Annotated[str | None, Header(alias="X-Status-Key")] = None,
) -> StatusResult:
    if service_key != settings.status_service_key:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "service authentication required")
    async with session_scope() as session:
        user = await session.get(User, payload.user_id)
        if user is None:
            return StatusResult(active=False, authz_version=None)
        return StatusResult(
            active=user.status == "active" and user.authz_version == payload.authz_version,
            authz_version=user.authz_version,
        )


@router.post("/register", response_model=Identity, status_code=status.HTTP_201_CREATED)
async def register_user(payload: Credentials) -> Identity:
    try:
        return Identity.model_validate(
            await register(payload.email, payload.password), from_attributes=True
        )
    except DuplicateEmailError as error:
        raise HTTPException(status.HTTP_409_CONFLICT, "email already registered") from error


@router.post("/verify", status_code=status.HTTP_204_NO_CONTENT)
async def confirm_email(payload: TokenInput) -> None:
    try:
        await verify_email(payload.token)
    except InvalidOneTimeTokenError as error:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid or expired token") from error


@router.post("/password-reset/request", status_code=status.HTTP_202_ACCEPTED)
async def reset_request(payload: ResetRequest) -> dict[str, str]:
    await request_password_reset(payload.email)
    return {"status": "accepted"}


@router.post("/password-reset/confirm", status_code=status.HTTP_204_NO_CONTENT)
async def reset_confirm(payload: ResetConfirm) -> None:
    try:
        await reset_password(payload.token, payload.password)
    except InvalidOneTimeTokenError as error:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid or expired token") from error


@router.post("/login", response_model=TokenBundle)
async def login(payload: Credentials) -> TokenBundle:
    try:
        return await issue_bundle((await authenticate(payload.email, payload.password)).user_id)
    except VerificationRequiredError as error:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "email verification required") from error
    except InvalidCredentialsError as error:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials") from error


@router.post("/refresh", response_model=TokenBundle)
async def refresh(payload: RefreshInput) -> TokenBundle:
    async with session_scope() as session:
        rotated = await rotate_refresh(session, payload.refresh_token)
    if rotated is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid refresh token")
    user_id, audience, new_refresh = rotated
    return await issue_bundle(user_id, audience, new_refresh)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(payload: RefreshInput) -> None:
    async with session_scope() as session:
        await revoke_refresh(session, payload.refresh_token)
