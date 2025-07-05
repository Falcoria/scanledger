from pydantic import BaseModel, Field
from typing import Optional
from uuid import UUID
from uuid import uuid4


class UserBase(BaseModel):
    email: Optional[str] = None
    isadmin: bool = False
    ip_counter: int = 0


class TokenBase(BaseModel):
    pass


class TokenIn(TokenBase):
    token_livetime: Optional[int] = None


class TokenOut(TokenBase):
    hashed_token: Optional[str] = None
    token_expires_at: Optional[int] = None


class UserIn(UserBase, TokenIn):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")


class UserOut(UserBase):
    id: UUID
    username: str


class UserAdminOut(UserOut):
    token_expires_at: Optional[int] = None


class UserPrivate(UserBase, TokenOut):
    id: UUID = Field(default_factory=uuid4)
    username: str = None
    #hashed_token: Optional[str] = None
    #token_expires_at: Optional[int] = None


class Token(BaseModel):
    token: str