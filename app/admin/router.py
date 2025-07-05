from typing import List

from fastapi import APIRouter, HTTPException, status, Body

from app.constants.messages import Message

from .schemas import (
    UserIn, 
    UserBase, 
    UserPrivate, 
    TokenIn,
    Token,
    UserAdminOut
)
from .service import (
    get_usersdb, 
    create_userdb, 
    update_userdb,
    delete_userdb,
    update_token_expiration_time,
    create_user_tokendb
)


admin_router = APIRouter()


@admin_router.get(
    "/users", 
    summary="Get users", 
    response_model=List[UserAdminOut]
)
async def index():
    """
    Get all users and associated data
    """
    users = await get_usersdb()
    if not users:
        return []
    return users


@admin_router.post(
    "/users",
    summary="Create user",
    status_code=status.HTTP_201_CREATED,
    response_description="Returns token to authenticate with",
    response_model=Token
)
async def create_user(
    user_data: UserIn
):
    """
    Create a new user and retreive token for it
    """
    #new_user = UserPrivate(**user_data.model_dump(exclude_unset=True))
    token = await create_userdb(user_data)
    if token is None:
        raise HTTPException(status_code=400, detail=Message.USER_ALREADY_EXISTS)

    return {"token": token}


@admin_router.put(
    "/users/{user_id}",
    summary="Update user",
    response_model=UserAdminOut
)
async def update_user(
    user_id: str, 
    user_data: UserBase
):
    """ Update a user's data by its name """
    change_user = UserPrivate(id=user_id, **user_data.model_dump(exclude_unset=True))
    updated_user = await update_userdb(change_user)
    if updated_user is None:
        raise HTTPException(status_code=404, detail=Message.USER_NOT_FOUND)
    return updated_user


@admin_router.delete(
    "/users/{user_id}",
    summary="Delete user",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_user(user_id: str):
    """ Delete a user by its name """
    result = await delete_userdb(user_id)
    if result is None:
        raise HTTPException(status_code=404, detail=Message.USER_NOT_FOUND)


@admin_router.post(
    "/users/{user_id}/token",
    summary="Change user's token",
    description="Deletes old token and creates a new one",
    response_model=Token
)
async def change_user_token(
    user_id: str,
    token_data: TokenIn = Body(..., description="Token data with new expiration time")
):
    """ Replace the token for a given user by its name """
    new_token = await create_user_tokendb(user_id, token_data.token_livetime)
    if new_token is None:
        raise HTTPException(status_code=404, detail=Message.USER_NOT_FOUND)
    
    return {"token": new_token}


@admin_router.put(
    "/users/{user_id}/token",
    summary="Update user's token expiration time",
    description="Updates the expiration time of the user's token",
)
async def update_user_token(
    user_id: str,
    token_data: TokenIn = Body(..., description="Token data with new expiration time")
):
    """ Update the token for a given user by its name """
    new_expires_at = await update_token_expiration_time(user_id, token_data.token_livetime)
    if new_expires_at is None:
        raise HTTPException(status_code=404, detail=Message.USER_NOT_FOUND)
    
    return {"new_expires_at": new_expires_at}