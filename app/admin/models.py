import uuid

from sqlmodel import SQLModel, Field, Relationship
from typing import Optional, List, TYPE_CHECKING

from app.projects.models import ProjectUserLink, ProjectDB


class UserDB(SQLModel, table=True):
    __tablename__ = "users"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    username: str = Field(index=True)
    hashed_token: Optional[str]
    email: Optional[str]
    isadmin: bool = False
    #ip_counter: int = 0
    # disabled: bool = False

    projects: List["ProjectDB"] = Relationship(back_populates="users", link_model=ProjectUserLink)