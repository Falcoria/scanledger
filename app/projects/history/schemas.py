from typing import Optional, Literal
from pydantic import BaseModel, Field, model_validator

from app.projects.filters import FilterOp, FilterConfig, OrderDir
from falcoria_common.schemas.enums.history import PortChangeType


class HistoryFilterParams(BaseModel):
    """Query filter parameters for history endpoints."""
    ip: Optional[str] = None
    port: Optional[int] = Field(default=None, ge=0, le=65535)
    change_type: Optional[PortChangeType] = None
    old_value: Optional[str] = None
    new_value: Optional[str] = None
    since: Optional[int] = Field(default=None, description="Unix timestamp, inclusive")
    until: Optional[int] = Field(default=None, description="Unix timestamp, inclusive")

    @model_validator(mode="after")
    def validate_date_range(self):
        if self.since is not None and self.until is not None and self.since > self.until:
            raise ValueError("since must be less than or equal to until")
        return self


HistoryFilterField = Literal["ip", "port", "change_type", "old_value", "new_value", "since", "until"]
HistoryOrderField = Literal["ip", "port", "change_type", "old_value", "new_value", "created_at"]

HISTORY_FILTER_CONFIG: dict[HistoryFilterField, FilterConfig] = {
    "ip":          FilterConfig(op=FilterOp.EXACT, field="ip"),
    "port":        FilterConfig(op=FilterOp.EXACT, field="port"),
    "change_type": FilterConfig(op=FilterOp.EXACT, field="change_type"),
    "old_value":   FilterConfig(op=FilterOp.ILIKE, field="old_value"),
    "new_value":   FilterConfig(op=FilterOp.ILIKE, field="new_value"),
    "since":       FilterConfig(op=FilterOp.GTE,   field="created_at"),
    "until":       FilterConfig(op=FilterOp.LTE,   field="created_at"),
}

assert set(HISTORY_FILTER_CONFIG.keys()) == set(HistoryFilterParams.model_fields.keys())


class HistoryPaginationParams(BaseModel):
    skip: Optional[int] = Field(default=None, ge=0)
    limit: Optional[int] = Field(default=None, gt=0)
    order_by: HistoryOrderField = "created_at"
    order_dir: OrderDir = OrderDir.DESC
