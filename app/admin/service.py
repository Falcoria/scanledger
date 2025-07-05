import time
from typing import List

from sqlmodel import select, update, delete

from app.logger import logger
from app.database import (
    get_session, 
    select_one, 
    select_many, 
    delete_and_commit
)

from .models import UserDB
from .schemas import UserPrivate, UserIn
from .utils import hash_password_without_salt, generate_secure_random_string


async def generate_unique_token(token_length=60):
    """
    Generates a unique token and checks if its hash already exists in the database.
    Continues to regenerate the token until a unique one is found.
    """
    while True:
        token = generate_secure_random_string(token_length)
        hashed_token = hash_password_without_salt(token)

        statement = select(UserDB).where(UserDB.hashed_token == hashed_token)
        result = await select_one(statement)
        if result is None:
            return token


async def get_usersdb() -> List[UserDB]:
    """ Get all users from the database """
    statement = select(UserDB)
    result = await select_many(statement)
    if result is None:
        return []
    
    return result


async def userdb_by_token(hashed_token: str) -> UserDB:
    """ Get a user by hashed token """
    statement = select(UserDB).where(UserDB.hashed_token == hashed_token)
    user_db = await select_one(statement)
    return user_db


async def create_userdb(user_data: UserIn):
    """Create a user in the database with optional token expiration."""
    new_user = UserPrivate(**user_data.model_dump(exclude_unset=True, exclude={"token_livetime"}))

    async with get_session() as session:
        plain_token = await generate_unique_token()
        hashed_token = hash_password_without_salt(plain_token)
        
        new_user.hashed_token = hashed_token
        
        # Handle expiration
        if user_data.token_livetime:
            new_user.token_expires_at = int(time.time()) + user_data.token_livetime
        else:
            new_user.token_expires_at = None
        
        user_db = UserDB.model_validate(new_user)

        try:
            session.add(user_db)
            await session.commit()
            return plain_token
        except Exception as e:
            logger.error(f"Create user exception: {e}")
            return None


def update_user_attributes(user: UserPrivate, user_db: UserDB):
    """ Update user attributes """
    for key, value in user.model_dump(exclude_unset=True).items():
        setattr(user_db, key, value)
    return user_db


async def update_userdb(user: UserPrivate) -> UserDB:
    """ Update a user in the database """
    async with get_session() as session:
        statement = select(UserDB).where(UserDB.id == user.id)
        result = await session.exec(statement)
        db_user = result.first()
        if not db_user:
            return None
        
        #upd_data = user.model_dump(exclude_unset=True, exclude={"username"})
        db_user = update_user_attributes(user, db_user)
        
        try:
            session.add(db_user)
            await session.commit()
            await session.refresh(db_user)
            return db_user
        except Exception as e:
            logger.error(f"Update user exception: {e}")
            return None


async def delete_userdb(user_id: str) -> bool:
    """ Delete a user from the database """
    statement = delete(UserDB).where(UserDB.id == user_id)
    result = await delete_and_commit(statement)
    return result


async def create_user_tokendb(user_id: str, token_livetime: int) -> str:
    """ Update a user's token in the database """
    async with get_session() as session:
        token_expires_at = int(time.time()) + token_livetime if token_livetime else None
        plain_token = await generate_unique_token()
        hashed_token = hash_password_without_salt(plain_token)
        statement = (
            update(UserDB)
            .where(UserDB.id == user_id)
            .values(
                hashed_token=hashed_token, 
                token_expires_at=token_expires_at
            )
        )

        try:
            await session.exec(statement)
            await session.commit()
            return plain_token
        except Exception as e:
            logger.error(f"Update user token exception: {e}")
            return None


async def update_token_expiration_time(user_id: str, token_livetime: int):
    """ Change a user's token and set its expiration time """
    async with get_session() as session:
        new_expires_at = int(time.time()) + token_livetime
        statement = (
            update(UserDB)
            .where(UserDB.id == user_id)
            .values(token_expires_at=new_expires_at)
        )

        try:
            await session.exec(statement)
            await session.commit()
            return new_expires_at
        except Exception as e:
            logger.error(f"Update token expiration time exception: {e}")
            return None