from typing import Optional, TYPE_CHECKING, List
from sqlmodel import SQLModel, Field, UniqueConstraint, Relationship, Column, Text, ForeignKey, Integer, JSON

if TYPE_CHECKING:
    from app.projects.ips.models import IPDB


class PortDB(SQLModel, table=True):
    __tablename__ = "ports"
    __table_args__ = (UniqueConstraint("number", "protocol", "ip_id"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    number: int = Field(index=True)
    protocol: str = Field(index=True)
    state: str
    reason: Optional[str]

    service: Optional[str] = Field(index=True)        # <service name="...">
    product: Optional[str] = Field(index=True)        # <service product="...">
    version: Optional[str]                            # <service version="...">
    extrainfo: Optional[str]                          # <service extrainfo="...">
    cpe: Optional[List[str]] = Field(default=None, sa_column=Column(JSON))  # list of CPEs
    servicefp: Optional[str]                          # <service servicefp="...">
    scripts: Optional[dict] = Field(default=None, sa_column=Column(JSON))   # script output as dict

    ip_id: Optional[int] = Field(
        sa_column=Column(
            Integer,
            ForeignKey("ips.id", ondelete="CASCADE"),
            default=None,
        )
    )
    ip_rel: Optional["IPDB"] = Relationship(back_populates="ports")

    #checks: Optional[List["PortCheckDB"]] = Relationship(back_populates="port", sa_relationship_kwargs={"cascade": "all, delete"})
    