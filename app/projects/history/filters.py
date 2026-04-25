from app.projects.filters import BUILDERS
from .models import IPPortHistoryDB
from .schemas import HistoryFilterParams, HISTORY_FILTER_CONFIG


def apply_history_filters(statement, filters: HistoryFilterParams):
    """Applies all active filters to the history SQL statement."""
    for name, cfg in HISTORY_FILTER_CONFIG.items():
        value = getattr(filters, name, None)
        if value is None:
            continue
        value = getattr(value, "value", value)
        if isinstance(value, str) and not value.strip():
            continue
        col = getattr(IPPortHistoryDB, cfg.field)
        statement = statement.where(BUILDERS[cfg.op](col, value))
    return statement
