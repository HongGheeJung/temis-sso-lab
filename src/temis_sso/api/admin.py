from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from temis_sso.api.users import current_subject
from temis_sso.application.admin import (
    AdminRequiredError,
    SelfActionError,
    UserNotFoundError,
    approve_user,
    change_role,
    revoke_sessions,
    suspend_user,
)

router = APIRouter(prefix="/admin", tags=["admin"])


class UserResult(BaseModel):
    user_id: str
    status: str


class SuspensionInput(BaseModel):
    reason: str = Field(min_length=3, max_length=200)


def translate(error: Exception) -> HTTPException:
    if isinstance(error, AdminRequiredError):
        return HTTPException(status.HTTP_403_FORBIDDEN, "current admin role required")
    if isinstance(error, SelfActionError):
        return HTTPException(status.HTTP_409_CONFLICT, "self action is not allowed")
    return HTTPException(status.HTTP_404_NOT_FOUND, "user not found")


@router.post("/users/{target_id}/approve", response_model=UserResult)
async def approve(target_id: str, actor_id: Annotated[str, Depends(current_subject)]) -> UserResult:
    try:
        user = await approve_user(actor_id, target_id)
        return UserResult(user_id=user.id, status=user.status)
    except (AdminRequiredError, SelfActionError, UserNotFoundError) as error:
        raise translate(error) from error


@router.post("/users/{target_id}/suspend", response_model=UserResult)
async def suspend(
    target_id: str,
    payload: SuspensionInput,
    actor_id: Annotated[str, Depends(current_subject)],
) -> UserResult:
    try:
        user = await suspend_user(actor_id, target_id, payload.reason)
        return UserResult(user_id=user.id, status=user.status)
    except (AdminRequiredError, SelfActionError, UserNotFoundError) as error:
        raise translate(error) from error


@router.put("/users/{target_id}/roles/{role}", status_code=status.HTTP_204_NO_CONTENT)
async def grant_role(
    target_id: str, role: str, actor_id: Annotated[str, Depends(current_subject)]
) -> None:
    try:
        await change_role(actor_id, target_id, role, True)
    except (AdminRequiredError, SelfActionError, UserNotFoundError) as error:
        raise translate(error) from error


@router.delete("/users/{target_id}/roles/{role}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_role(
    target_id: str, role: str, actor_id: Annotated[str, Depends(current_subject)]
) -> None:
    try:
        await change_role(actor_id, target_id, role, False)
    except (AdminRequiredError, SelfActionError, UserNotFoundError) as error:
        raise translate(error) from error


@router.post("/users/{target_id}/revoke-sessions", status_code=status.HTTP_204_NO_CONTENT)
async def revoke(target_id: str, actor_id: Annotated[str, Depends(current_subject)]) -> None:
    try:
        await revoke_sessions(actor_id, target_id)
    except (AdminRequiredError, SelfActionError, UserNotFoundError) as error:
        raise translate(error) from error
