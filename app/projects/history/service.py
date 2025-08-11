from typing import Optional

from sqlmodel import select, delete

from app.projects.ports.schemas import PortIn
from app.projects.ports.models import PortDB
from app.projects.history.models import IPPortHistoryDB
from falcoria_common.schemas.enums.history import PortChangeType
from app.database import select_many, delete_and_commit

from app.projects.utils import unix_now


def detect_port_change_entry(
    project_id: str,
    ip: str,
    new_port: PortIn,
    old_port: PortDB,
    created_at: int | None = None
) -> Optional[IPPortHistoryDB]:
    created_at = created_at or unix_now()

    if new_port.state != str(old_port.state):
        change_type = PortChangeType.STATE
        old = old_port.state
        new = new_port.state
    elif new_port.service != old_port.service:
        change_type = PortChangeType.SERVICE
        old = old_port.service
        new = new_port.service
    elif new_port.product != old_port.product:
        change_type = PortChangeType.PRODUCT
        old = old_port.product
        new = new_port.product
    elif new_port.version != old_port.version:
        change_type = PortChangeType.VERSION
        old = old_port.version
        new = new_port.version
    else:
        return None

    return IPPortHistoryDB(
        project_id=project_id,
        ip=ip,
        port=new_port.number,
        protocol=new_port.protocol,
        change_type=change_type,
        old_value=old,
        new_value=new,
        created_at=created_at
    )


async def get_ip_port_historiesdb(project_id: str) -> list[IPPortHistoryDB]:
    """
    Retrieves the port history for a given project.
    Returns a list of IPPortHistory entries.
    """
    statement = select(IPPortHistoryDB).where(
        IPPortHistoryDB.project_id == project_id
    )

    results = await select_many(statement)
    return [IPPortHistoryDB.model_validate(item) for item in results] if results else []


async def get_ip_port_historydb(project_id: str, ip: str) -> list[IPPortHistoryDB]:
    statement = select(IPPortHistoryDB).where(
        IPPortHistoryDB.project_id == project_id,
        IPPortHistoryDB.ip == ip
    )

    results = await select_many(statement)
    return [IPPortHistoryDB.model_validate(item) for item in results] if results else []
    

async def delete_ip_port_historydb(project_id: str) -> bool | None:
    statement = delete(IPPortHistoryDB).where(
        IPPortHistoryDB.project_id == project_id
    )
    result = await delete_and_commit(statement)
    return result