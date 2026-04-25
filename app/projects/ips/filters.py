from typing import Callable, Any

from sqlalchemy import and_
from app.projects.ports.models import PortDB
from app.projects.hosts.models import HostDB
from app.projects.filters import BUILDERS, FilterOp
from .models import IPDB
from .schemas import IPFilterParams, FILTER_CONFIG, FilterModel


MODEL_MAP = {
    FilterModel.IP:   IPDB,
    FilterModel.PORT: PortDB,
    FilterModel.HOST: HostDB,
}

APPLIERS: dict[FilterModel, Callable[[Any, Any], Any]] = {
    FilterModel.IP:   lambda stmt, cond: stmt.where(cond),
    FilterModel.PORT: lambda stmt, cond: stmt.where(IPDB.ports.any(cond)),  # type: ignore[union-attr]
    FilterModel.HOST: lambda stmt, cond: stmt.where(IPDB.hostnames.any(cond)),  # type: ignore[union-attr]
}


def build_port_conditions(filters: IPFilterParams) -> list:
    """Returns SQLAlchemy conditions for port fields only — used for selectinload filtering."""
    conditions = []
    for name, cfg in FILTER_CONFIG.items():
        if cfg.model != FilterModel.PORT:
            continue
        value = getattr(filters, name, None)
        if value is None or (isinstance(value, str) and not value.strip()):
            continue
        value = getattr(value, "value", value)
        conditions.append(BUILDERS[cfg.op](getattr(PortDB, cfg.field), value))
    return conditions


def apply_filters(statement, filters: IPFilterParams):
    """Applies all active filters. All port conditions combined into single any() to match within one port."""
    for name, cfg in FILTER_CONFIG.items():
        if cfg.model == FilterModel.PORT:
            continue
        value = getattr(filters, name, None)
        if value is None:
            continue
        value = getattr(value, "value", value)
        if isinstance(value, str) and not value.strip():
            continue
        col = getattr(MODEL_MAP[cfg.model], cfg.field)
        statement = APPLIERS[cfg.model](statement, BUILDERS[cfg.op](col, value))

    port_conditions = build_port_conditions(filters)
    if port_conditions:
        statement = statement.where(IPDB.ports.any(and_(*port_conditions)))  # type: ignore[union-attr]

    return statement
