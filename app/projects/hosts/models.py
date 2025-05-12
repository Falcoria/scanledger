import uuid

from sqlmodel import (
    SQLModel, 
    Column, 
    Text, 
    ForeignKey, 
    UniqueConstraint,
    Integer,
    UUID,
    Field, 
    Relationship,
    
)
from typing import Optional, TYPE_CHECKING, List


if TYPE_CHECKING:
    from app.projects.models import ProjectDB
    from app.projects.ips.models import IPDB


class HostIPLink(SQLModel, table=True):
    __tablename__ = 'host_ip_link'
    ip: str = Field(
        sa_column=Column(Integer, ForeignKey("ips.id", ondelete="CASCADE"), primary_key=True)
    )
    hostname: str = Field(
        sa_column=Column(Integer, ForeignKey("hosts.id", ondelete="CASCADE"), primary_key=True)
    )


class HostDB(SQLModel, table=True):
    __tablename__ = 'hosts'
    __table_args__ = (UniqueConstraint('hostname', 'project_id',),)

    id: Optional[int] = Field(default=None, primary_key=True)
    hostname: Optional[str]
    description: Optional[str]

    project_id: Optional[str] = Field(
        sa_column=Column(
            UUID,
            ForeignKey("projects.id", ondelete="CASCADE"),
            default=None
        )
    )

    ips: Optional[List['IPDB']] = Relationship(back_populates='hostnames', link_model=HostIPLink)
    project: Optional["ProjectDB"] = Relationship(back_populates="hosts")
    #urls: Optional[List["UrlDB"]] = Relationship(back_populates='host', sa_relationship_kwargs={"lazy": "joined"})