import uuid
from datetime import date
from typing import Optional, List, TYPE_CHECKING

from sqlmodel import SQLModel, Relationship, Field, Column, ForeignKey, String, UUID

from app.projects.ips.models import IPDB
#from app.projects.credentials.models import CredentialDB
from app.projects.hosts.models import HostDB

if TYPE_CHECKING:
    from app.admin.models import UserDB
    
    
class ProjectUserLink(SQLModel, table=True):
    project_id: UUID = Field(
        default=None, 
        sa_column=Column(UUID, ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True)
    )
    user_id: UUID = Field(
        default=None, 
        sa_column=Column(UUID, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    )

    class Config:
        arbitrary_types_allowed = True


class ProjectDB(SQLModel, table=True):
    __tablename__ = "projects"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True, unique=True)
    project_name: str = Field(default=None, index=True)
    #start_date: Optional[date]
    #end_date: Optional[date]
    #scope: Optional[str] = Field(sa_column=Column(JSON))
    # archived: Optional[bool] = False

    users: List["UserDB"] = Relationship(back_populates="projects", link_model=ProjectUserLink, sa_relationship_kwargs={"lazy": "joined"})
    ips: List["IPDB"] = Relationship(back_populates="project", sa_relationship_kwargs={"cascade": "all, delete"})
    #creds: List["CredentialDB"] = Relationship(back_populates="project", sa_relationship_kwargs={"cascade": "all, delete"})
    hosts: List["HostDB"] = Relationship(back_populates="project", sa_relationship_kwargs={"cascade": "all, delete"})
