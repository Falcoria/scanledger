from fastapi import APIRouter, HTTPException, status

from app.constants.messages import Message
from falcoria_common.schemas.history import IPPortHistoryOut

from .service import (
    get_ip_port_historydb, 
    get_ip_port_historiesdb,
    delete_ip_port_historydb
)


history_router = APIRouter()


@history_router.get("", response_model=list[IPPortHistoryOut])
async def get_port_history(
    project_id: str,
):
    ip_port_history = await get_ip_port_historiesdb(project_id)
    if not ip_port_history:
        raise HTTPException(
            status_code=404,
            detail=Message.NO_HISTORY
        )
    return ip_port_history


@history_router.get("/{ip}", response_model=list[IPPortHistoryOut])
async def get_ip_port_history(
    project_id: str,
    ip: str,
):
    ip_port_history = await get_ip_port_historydb(project_id, ip)
    if not ip_port_history:
        raise HTTPException(
            status_code=404,
            detail=Message.NO_HISTORY_FOR_IP.format(ip=ip)
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