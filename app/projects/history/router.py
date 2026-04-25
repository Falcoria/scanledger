from typing import Annotated

from fastapi import APIRouter, HTTPException, status, Depends

from app.constants.messages import Message
from falcoria_common.schemas.history import IPPortHistoryOut

from .schemas import HistoryFilterParams, HistoryPaginationParams
from .service import (
    get_ip_port_historiesdb,
    delete_ip_port_historydb
)


history_router = APIRouter()


@history_router.get("", response_model=list[IPPortHistoryOut])
async def get_port_history(
    project_id: str,
    filters: Annotated[HistoryFilterParams, Depends()] = None,
    pagination: Annotated[HistoryPaginationParams, Depends()] = None,
):
    ip_port_history = await get_ip_port_historiesdb(project_id, filters, pagination)
    if not ip_port_history:
        raise HTTPException(
            status_code=404,
            detail=Message.NO_HISTORY
        )
    return ip_port_history



@history_router.delete(
        "",
        status_code=status.HTTP_204_NO_CONTENT
    )
async def delete_port_history(
    project_id: str,
):
    result = await delete_ip_port_historydb(project_id)
    if not result:
        raise HTTPException(
            status_code=404,
            detail=Message.NO_HISTORY
        )