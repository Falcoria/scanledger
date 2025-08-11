from typing import Optional
from datetime import datetime, timezone
from uuid import UUID

from sqlmodel import SQLModel, Field, Column, ForeignKey, UniqueConstraint, Integer, String

from app.projects.utils import unix_now
from falcoria_common.schemas.enums.history import PortChangeType


def utc_now_naive():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class IPPortHistoryDB(SQLModel, table=True):
    __tablename__ = "ip_port_history"
    __table_args__ = (
        UniqueConstraint("project_id", "ip", "port", "protocol", "change_type", "created_at"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    
    project_id: UUID = Field(
        sa_column=Column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    )
    ip: str = Field(index=True)
    port: int = Field(sa_column=Column(Integer, index=True))
    protocol: str = Field(sa_column=Column(String, index=True))

    change_type: PortChangeType = Field(
        sa_column=Column(String, index=True, nullable=False)
    )
    old_value: Optional[str]
    new_value: Optional[str]

    created_at: int = Field(default_factory=unix_now, nullable=False)