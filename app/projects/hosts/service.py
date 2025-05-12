from typing import List

from sqlmodel import select, delete
from sqlalchemy.orm import joinedload
from sqlmodel.ext.asyncio.session import AsyncSession
from app.database import get_session, delete_and_commit

from app.projects.ips.models import IPDB

from .models import HostDB


async def get_hostsdb_session_in(
        session: AsyncSession,
        hostnames: List[str],
        project_id: str
    ) -> List[HostDB]:
        """
        Get Hosts from hostnames list for project_name without creating new session
        """
        statement = (
            select(HostDB)
            .where(HostDB.project_id == project_id)
            .where(HostDB.hostname.in_(hostnames))
            .options(
                joinedload(HostDB.ips)
                .joinedload(IPDB.ports),
                #joinedload(HostDB.urls)
            )
        )
        result = await session.exec(statement)
        hostsdb = result.unique().all()
        return hostsdb


async def get_only_hostsdb_session(
        session: AsyncSession,
        hostnames: List[str],
        project_id: str
    ) -> List[HostDB]:
        """
        Get Hosts from hostnames list for project_name without creating new session
        """
        statement = (
            select(HostDB)
            .where(HostDB.project_id == project_id)
            .where(HostDB.hostname.in_(hostnames))
            .options(
                joinedload(HostDB.ips)
            )
        )
        result = await session.exec(statement)
        hostsdb = result.unique().all()
        return hostsdb


async def delete_hostsdb(project_id: str) -> bool | None:
    """
    Deletes all Hosts from database
    """
    statement = delete(HostDB).where(HostDB.project_id == project_id)
    result = await delete_and_commit(statement)
    return result