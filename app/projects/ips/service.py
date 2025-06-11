from typing import List, Dict, Any

from sqlmodel import select, delete
from sqlalchemy.orm import joinedload
from sqlmodel.ext.asyncio.session import AsyncSession

from app.database import select_many, delete_and_commit, get_session, select_one, insert_and_refresh
from app.projects.ports.schemas import PortIn
from app.projects.ports.service import port_scheme2model
from app.projects.report_processing.nmap_to_ip_converter import nmap_report_to_ipdict
from app.projects.utils import read_and_decode_file
from app.projects.parsers import nmap_exporters
from app.projects.hosts.models import HostDB

from .models import IPDB
from .schemas import IPIn, ImportMode, DownloadReportFormat, BaseIPIn


# ================================
# GET / DELETE FUNCTIONS
# ================================

async def get_ipsdb(
    project_id: str,
    skip: int | None,
    limit: int | None,
    has_ports: bool | None = None
) -> List[IPDB]:
    """
    Retrieves all IPs from the database for the specified project.
    """
    statement = (
        select(IPDB)
        .where(IPDB.project_id == project_id)
        .order_by(IPDB.ip)
        .options(
            joinedload(IPDB.ports),
            joinedload(IPDB.hostnames)
        )
        .offset(skip)
        .limit(limit)
    )
    if has_ports:
        statement = statement.where(IPDB.ports.any())

    return await select_many(statement)


async def delete_ipsdb(project_id: str) -> bool | None:
    """
    Deletes all HostDB and IPDB records for the specified project.
    Ensures both deletions happen in the same transaction.
    """
    async with get_session() as session:
        try:
            # Delete HostDB entries first
            stmt_hosts = delete(HostDB).where(HostDB.project_id == project_id)
            await session.exec(stmt_hosts)

            # Then delete IPDB entries
            stmt_ips = delete(IPDB).where(IPDB.project_id == project_id)
            await session.exec(stmt_ips)

            await session.commit()
            return True

        except Exception:
            await session.rollback()
            return None


# ================================
# DEDUPLICATION
# ================================

def merge_hostnames(existing: List[str], new: List[str]) -> List[str]:
    """
    Merge two hostname lists and remove duplicates.
    """
    return list(set(existing or []) | set(new or []))


def process_ip_entry(unique_ips: Dict[str, IPIn], ip_entry: IPIn) -> None:
    """
    Adds or merges an IP entry into a dictionary keyed by IP address.
    Ensures hostnames inside the IP entry are deduplicated.
    """
    # Deduplicate hostnames inside the incoming IPIn before any merge
    ip_entry.hostnames = list(set(ip_entry.hostnames or []))

    ip_address = ip_entry.ip

    if ip_address in unique_ips:
        unique = unique_ips[ip_address]
        # Merge hostnames from both entries (no duplicates possible now)
        unique.hostnames = merge_hostnames(
            unique.hostnames,
            ip_entry.hostnames
        )
        # (Optional: here you could also merge metadata or other fields if needed)
    else:
        unique_ips[ip_address] = ip_entry


def delete_ip_duplicates_merge_hosts(ips: List[IPIn]) -> List[IPIn]:
    """
    Deduplicates IPs by merging hostnames for the same IP address.
    Also ensures no duplicates inside individual IP entries.
    """
    unique_ips = {}
    for ip_entry in ips:
        process_ip_entry(unique_ips, ip_entry)
    return list(unique_ips.values())



# ================================
# MAPPING EXISTING DB ENTRIES
# ================================

async def get_ipsdb_session_in(
    session: AsyncSession,
    ip_addrs: List[str],
    project_name: str
) -> List[IPDB]:
    """
    Fetches IPDB entries for given IP addresses in the specified project.
    """
    statement = (
        select(IPDB)
        .where(IPDB.ip.in_(ip_addrs))
        .where(IPDB.project_id == project_name)
        .options(
            joinedload(IPDB.ports),
            joinedload(IPDB.hostnames)
        )
    )
    result = await session.exec(statement)
    return result.unique().all()


async def get_map_ips_ipdbs(
    session: AsyncSession,
    ips: List[str],
    project_id: str
) -> Dict[str, IPDB]:
    """
    Maps IP addresses to existing IPDB entries.
    """
    existing_ipsdb = await get_ipsdb_session_in(session, ips, project_id)
    return {ip.ip: ip for ip in existing_ipsdb}


def get_unique_hostnames_from_ips(
    ips: List[IPIn]
) -> List[str]:
    return list(set(
        hostname
        for ip in ips
        for hostname in (ip.hostnames or [])
    ))


async def build_hostname_to_hostdb_map(
    session: AsyncSession,
    ips: List[IPIn],
    project_id: str
) -> Dict[str, HostDB]:
    """
    1. Extract all unique hostnames.
    2. Query HostDB for existing.
    3. Create missing HostDBs but don't commit yet.
    """
    hostnames = get_unique_hostnames_from_ips(ips)
    existing_hosts = {}

    if hostnames:
        stmt = (
            select(HostDB)
            .where(HostDB.hostname.in_(hostnames))
            .where(HostDB.project_id == project_id)
        )
        result = await session.exec(stmt)
        existing_hosts = {host.hostname: host for host in result.unique().all()}

    # Create missing hostnames
    for hostname in hostnames:
        if hostname not in existing_hosts:
            existing_hosts[hostname] = HostDB(
                hostname=hostname,
                project_id=project_id
            )

    return existing_hosts
    

async def bind_hostnames_to_hostdbs(
    session: AsyncSession,
    ips: List[IPIn],
    project_id: str
) -> None:
    """
    Maps hostnames to HostDB objects and binds them into IPIn.hostnames in place.
    Assumes hostnames in IPIn are already deduplicated.
    """
    hostname_to_hostdb = await build_hostname_to_hostdb_map(
        session,
        ips,
        project_id
    )

    for ip in ips:
        ip.hostnames = [
            hostname_to_hostdb[hostname] for hostname in ip.hostnames or []
        ]


# ================================
# CONVERSION SCHEME -> MODEL
# ================================

def ip_scheme2model(
    ip: IPIn,
    project_id: str
) -> IPDB:
    """
    Converts an IPIn schema to an IPDB model instance.
    """
    ip_data = ip.model_dump(exclude={"ports", "hostnames"})
    ipdb = IPDB(**ip_data, project_id=project_id)
    ipdb.hostnames = ip.hostnames or []

    for port in ip.ports or []:
        if isinstance(port, dict):
            port = PortIn(**port)
        ipdb.ports.append(port_scheme2model(port))

    return ipdb


# ================================
# PORT PROCESSING UTILITIES
# ================================

def update_ipdb_attributes(ipdb: IPDB, update_data: Dict[Any, Any]) -> None:
    """
    Updates metadata fields (excluding ports and hostnames) in an IPDB.
    """
    for key, value in update_data.items():
        if key not in {"ports", "hostnames"}:
            setattr(ipdb, key, value)


def add_port_to_ipdb(ipdb: IPDB, port: PortIn | Dict[Any, Any]):
    if isinstance(port, dict):
        port = PortIn(**port)
    ipdb.ports.append(port_scheme2model(port))


def process_ports_in_data(ipdb: IPDB, new_ports: List[PortIn | Dict[Any, Any]]):
    ipdb.ports = []
    for port in new_ports:
        add_port_to_ipdb(ipdb, port)


def update_ipdb(ipdb: IPDB, update_ip_data: Dict[Any, Any]):
    update_ipdb_attributes(ipdb, update_ip_data)


def replace_ipdb_ports(ipdb: IPDB, new_ports: List[PortIn | Dict[Any, Any]]):
    process_ports_in_data(ipdb, new_ports)


def update_ipdb_ports(
    ipdb: IPDB,
    incoming_ports: List[PortIn | Dict[Any, Any]]
):
    """
    Updates existing ports in-place or adds new ports.
    """
    existing_ports = {(p.number, p.protocol): p for p in ipdb.ports}

    for port_data in incoming_ports:
        if isinstance(port_data, dict):
            port_data = PortIn(**port_data)

        key = (port_data.number, port_data.protocol)
        existing_port = existing_ports.get(key)

        if existing_port:
            for field, value in port_data.model_dump(exclude_unset=True, exclude_none=True).items():
                if value not in [None, ""]:
                    setattr(existing_port, field, value)
        else:
            ipdb.ports.append(port_scheme2model(port_data))


def update_ipdb_hostnames(existing_ipdb: IPDB, new_hostdbs: List[HostDB]) -> bool:
    """
    Merges new HostDB objects into the IPDB hostnames list without duplicates.
    Returns True if any new hostnames were added, False otherwise.
    """
    existing_hostnames = {host.hostname for host in existing_ipdb.hostnames or []}
    updated = False

    for host in new_hostdbs:
        if host.hostname not in existing_hostnames:
            existing_ipdb.hostnames.append(host)
            existing_hostnames.add(host.hostname)
            updated = True

    return updated


# ================================
# MODE IMPLEMENTATIONS
# ================================

async def create_ipsdb_insert(
    session: AsyncSession,
    project_id: str,
    new_ips: List[IPIn],
    map_existing_ipdbs: Dict[str, IPDB]
) -> List[str]:
    """
    INSERT mode:
    - Creates new IPs only
    - Merges hostnames for existing IPs
    - Skips modifying ports or other metadata for existing IPs
    """
    ipsdbs = []
    updated_ips = []

    for ip in new_ips:
        existing_ipdb = map_existing_ipdbs.get(ip.ip)

        if not existing_ipdb:
            # Insert new IP
            ipdb = ip_scheme2model(ip, project_id)
            ipsdbs.append(ipdb)
        else:
            if update_ipdb_hostnames(existing_ipdb, ip.hostnames or []):
                session.add(existing_ipdb)
                updated_ips.append(existing_ipdb.ip)

    if ipsdbs or updated_ips:
        if ipsdbs:
            session.add_all(ipsdbs)
        await session.commit()

    # Return all IPs that were created or had hostnames merged
    return [ip.ip for ip in ipsdbs] + updated_ips


async def create_ipsdb_replace(
    session: AsyncSession,
    project_id: str,
    new_ips: List[IPIn],
    map_existing_ipdbs: Dict[str, IPDB]
) -> List[str]:
    """
    REPLACE mode:
    - Overwrites metadata.
    - Replaces ports.
    - Reassigns hostnames (old links discarded).
    """
    newly_added_ips = []

    for ip in new_ips:
        existing_ipdb = map_existing_ipdbs.get(ip.ip)

        if existing_ipdb:
            update_ipdb(existing_ipdb, ip.model_dump(exclude_unset=True))
            replace_ipdb_ports(existing_ipdb, ip.ports or [])
            existing_ipdb.hostnames = list(ip.hostnames or [])
            session.add(existing_ipdb)
            newly_added_ips.append(existing_ipdb.ip)
        else:
            ipdb = ip_scheme2model(ip, project_id)
            ipdb.hostnames = list(ip.hostnames or [])
            session.add(ipdb)
            newly_added_ips.append(ipdb.ip)

    if newly_added_ips:
        await session.commit()

    return newly_added_ips


async def create_ipsdb_update(
    session: AsyncSession,
    project_id: str,
    new_ips: List[IPIn],
    map_existing_ipdbs: Dict[str, IPDB]
) -> List[str]:
    """
    UPDATE mode:
    - Updates metadata only for fields provided in input
    - Updates existing ports and adds new ports
    - Merges hostnames
    """
    updated_ips = []

    for ip in new_ips:
        existing_ipdb = map_existing_ipdbs.get(ip.ip)

        if existing_ipdb:
            update_ipdb(existing_ipdb, ip.model_dump(exclude_unset=True))
            update_ipdb_ports(existing_ipdb, ip.ports or [])
            update_ipdb_hostnames(existing_ipdb, ip.hostnames or [])

            session.add(existing_ipdb)
            updated_ips.append(existing_ipdb.ip)

        else:
            ipdb = ip_scheme2model(ip, project_id)
            session.add(ipdb)
            updated_ips.append(ipdb.ip)

    if updated_ips:
        await session.commit()

    return updated_ips


def append_ipdb_ports(ipdb: IPDB, new_ports: List[PortIn | Dict[Any, Any]]) -> None:
    """
    Adds only missing ports to the existing IPDB without modifying existing ports.
    """
    existing_ports = {(p.number, p.protocol) for p in ipdb.ports}

    for port in new_ports or []:
        if isinstance(port, dict):
            port = PortIn(**port)

        key = (port.number, port.protocol)
        if key not in existing_ports:
            ipdb.ports.append(port_scheme2model(port))


async def create_ipsdb_append(
    session: AsyncSession,
    project_id: str,
    new_ips: List[IPIn],
    map_existing_ipdbs: Dict[str, IPDB]
) -> List[str]:
    """
    APPEND mode:
    - Does not change metadata
    - Merges hostnames
    - Appends new ports (does not change existing ones)
    """
    updated_ips = []

    for ip in new_ips:
        existing_ipdb = map_existing_ipdbs.get(ip.ip)

        if existing_ipdb:
            append_ipdb_ports(existing_ipdb, ip.ports or [])
            update_ipdb_hostnames(existing_ipdb, ip.hostnames or [])
            session.add(existing_ipdb)
            updated_ips.append(existing_ipdb.ip)
        else:
            ipdb = ip_scheme2model(ip, project_id)
            session.add(ipdb)
            updated_ips.append(ipdb.ip)

    if updated_ips:
        await session.commit()

    return updated_ips


# ================================
# MAIN CONTROLLER
# ================================

async def create_ipsdb(
    project_id: str,
    new_ips: List[IPIn],
    mode: ImportMode
) -> List[str] | None:
    """
    Creates or updates IPDB entries depending on the specified mode.
    """
    unique_ips = delete_ip_duplicates_merge_hosts(new_ips)
    if not unique_ips:
        return None

    new_ip_addrs = [ip.ip for ip in unique_ips]

    async with get_session() as session:
        map_existing_ipdbs = await get_map_ips_ipdbs(
            session,
            new_ip_addrs,
            project_id
        )

        await bind_hostnames_to_hostdbs(
            session,
            unique_ips,
            project_id
        )

        if mode == ImportMode.INSERT:
            return await create_ipsdb_insert(
                session,
                project_id,
                unique_ips,
                map_existing_ipdbs
            )
        elif mode == ImportMode.REPLACE:
            return await create_ipsdb_replace(
                session,
                project_id,
                unique_ips,
                map_existing_ipdbs
            )
        elif mode == ImportMode.UPDATE:
            return await create_ipsdb_update(
                session,
                project_id,
                unique_ips,
                map_existing_ipdbs
            )
        elif mode == ImportMode.APPEND:
            return await create_ipsdb_append(
                session,
                project_id,
                unique_ips,
                map_existing_ipdbs
            )


# ================================
# FILE UPLOAD
# ================================
async def import_ipsdb(project_name, report_file: Any, mode: ImportMode) -> List[IPDB] | None:
    """
    Import IPs from uploaded Nmap XML report into the database.
    """
    report_content = await read_and_decode_file(report_file)
    if not report_content:
        return None

    ips_report = nmap_report_to_ipdict(report_content)
    if not ips_report:
        return None
    
    new_ips = [IPIn(**new_ip) for new_ip in ips_report]
    result = await create_ipsdb(project_name, new_ips, mode)
    return result


# ================================
# DOWNLOAD REPORT
# ================================

async def download_ipsdb_report(
    project_id: str,
    skip: int | None = None,
    limit: int | None = None,
    has_ports: bool | None = None,
    format: DownloadReportFormat = DownloadReportFormat.XML
) -> str | None:
    """
    Downloads IPs from the database for the specified project and returns report as a file.
    """
    ips = await get_ipsdb(project_id, skip, limit, has_ports)

    if not ips:
        return None

    report = ""
    if format == DownloadReportFormat.XML:
        report = nmap_exporters.export_ips_to_xml(ips)
    #elif format == DownloadReportFormat.JSON:
    #    report = nmap_exporters.exports_ips_to_json(ips)
    #elif format == DownloadReportFormat.CSV:
    #    report = export_ips_to_csv(ips)
    else:
        return None

    return report


async def modify_ipdb(
    project_id: str,
    ip_address: str,
    ip_data: BaseIPIn
) -> IPDB | None:
    """
    Modifies a single IPDB record based on provided update data.
    Supports updating metadata, ports, and hostnames.
    """
    async with get_session() as session:
        ipdb = await select_one(
            select(IPDB)
            .where(
                IPDB.project_id == project_id,
                IPDB.ip == ip_address
            )
            .options(
                joinedload(IPDB.ports),
                joinedload(IPDB.hostnames)
            )
        )

        if not ipdb:
            return None

        data = ip_data.model_dump(exclude_unset=True)

        # --- Metadata ---
        update_ipdb_attributes(ipdb, data)

        # --- Ports ---
        if ports := data.get("ports"):
            update_ipdb_ports(ipdb, ports)

        # --- Hostnames ---
        if hostnames := set(data.get("hostnames") or []):
            hostname_map = await build_hostname_to_hostdb_map(
                session,
                [IPIn(ip=ip_address, hostnames=list(hostnames))],
                project_id
            )
            hostdbs = [hostname_map[name] for name in hostnames]
            update_ipdb_hostnames(ipdb, hostdbs)

        await insert_and_refresh(ipdb)
        return ipdb


async def get_ipdb(
    project_id: str,
    ip_address: str
) -> IPDB | None:
    """
    Retrieves a single IPDB record based on project ID and IP address.
    """
    statement = (
        select(IPDB)
        .where(
            IPDB.project_id == project_id,
            IPDB.ip == ip_address
        )
        .options(
            joinedload(IPDB.ports),
            joinedload(IPDB.hostnames)
        )
    )
    return await select_one(statement)


async def delete_ipdb(
    project_id: str,
    ip_address: str
) -> bool | None:
    """
    Deletes a single IPDB record based on project ID and IP address.
    """
    statement = (
        delete(IPDB)
        .where(
            IPDB.project_id == project_id,
            IPDB.ip == ip_address
        )
    )
    return await delete_and_commit(statement)


