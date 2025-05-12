from typing import Optional, List, TYPE_CHECKING

from sqlmodel import SQLModel, Field, UniqueConstraint, Relationship, Column, Text, ForeignKey, Integer

#from app.projects.port_checks.models import PortCheckDB

if TYPE_CHECKING:
    from app.projects.ips.models import IPDB


class PortDB(SQLModel, table=True):
    __tablename__ = "ports"
    __table_args__ = (UniqueConstraint('number', 'protocol', 'ip_id'),)

    id: Optional[int] = Field(default=None, primary_key=True)
    number: int  = Field(index=True)
    protocol: str = Field(index=True)
    state: str
    reason: Optional[str]
    banner: Optional[str] = Field(index=True)
    service: Optional[str] = Field(index=True)
    servicefp: Optional[str]
    scripts: Optional[str]

    ip_id: Optional[int] = Field(
        sa_column=Column(
            Integer,
            ForeignKey("ips.id", ondelete="CASCADE"),
            default=None
        )
    )
    ip_rel: Optional["IPDB"] = Relationship(back_populates="ports")
    
    #checks: Optional[List["PortCheckDB"]] = Relationship(back_populates="port", sa_relationship_kwargs={"cascade": "all, delete"})
    