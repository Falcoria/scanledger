from typing import Callable, Any
from enum import Enum

from pydantic import BaseModel


class FilterOp(str, Enum):
    EXACT = "exact"
    ILIKE = "ilike"
    PREFIX = "prefix"
    GTE = "gte"
    LTE = "lte"


class FilterConfig(BaseModel):
    """Describes how a single filter field is applied: operator and DB field name."""
    op: FilterOp
    field: str


class OrderDir(str, Enum):
    ASC = "asc"
    DESC = "desc"


BUILDERS: dict[FilterOp, Callable[[Any, Any], Any]] = {
    FilterOp.EXACT:  lambda col, v: col == v,
    FilterOp.ILIKE:  lambda col, v: col.ilike(f"%{v}%"),
    FilterOp.PREFIX: lambda col, v: col.ilike(f"{v}%"),
    FilterOp.GTE:    lambda col, v: col >= v,
    FilterOp.LTE:    lambda col, v: col <= v,
}
