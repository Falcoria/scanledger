import uuid
from datetime import date
from typing import Optional, List, TYPE_CHECKING

from sqlmodel import SQLModel, Relationship, Field, Column, ForeignKey, Text, UniqueConstraint, UUID

from app.projects.ports.models import PortDB
from app.projects.hosts.models import HostIPLink, HostDB

if TYPE_CHECKING:
    from app.projects.models import ProjectDB


class IPDB(SQLModel, table=True):
    __tablename__ = "ips"
    __table_args__ = (UniqueConstraint('ip', 'project_id',),)

    id: int = Field(default=None, primary_key=True)
    ip: Optional[str] = Field(index=True)
    asnName: Optional[str] = None
    orgName: Optional[str] = None
    status: Optional[str] = None
    os: Optional[str] = None
    endtime: Optional[int] = None

    project_id: str | None = Field(
        sa_column=Column(
            UUID,
            ForeignKey("projects.id", ondelete="CASCADE"),
            default=None
        )
    )
    project: Optional["ProjectDB"] = Relationship(back_populates="ips")
    ports: Optional[List["PortDB"]] = Relationship(back_populates="ip_rel", sa_relationship_kwargs={"cascade": "all, delete"})
    hostnames: Optional[List['HostDB']] = Relationship(back_populates='ips', link_model=HostIPLink)
    