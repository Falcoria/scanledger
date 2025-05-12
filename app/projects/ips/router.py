from typing import List, Annotated

from fastapi import (
    APIRouter, 
    status, 
    HTTPException,
    Query,
    Body,
    Depends,
)
from fastapi.responses import Response

from app.constants.messages import Message
from app.projects.ips.schemas import IPIn, IPOut, BaseIPIn
from app.projects.dependencies import file_upload

from .service import (
    get_ipsdb,
    delete_ipsdb,
    create_ipsdb,
    import_ipsdb,
    download_ipsdb_report,
    get_ipdb,
    delete_ipdb,
    modify_ipdb
)
from .schemas import ImportMode, DownloadReportFormat


ips_router = APIRouter()


@ips_router.get(
    "",
    response_model=List[IPOut],
    summary="Get IPs",
    tags=["projects:ips"],
)
async def get_ips(
    project_id: str,
    skip: Annotated[int | None, Query(ge=0)] = None,
    limit: Annotated[int | None, Query(ge=0)] = None,
    has_ports: Annotated[bool, Query()] = True,
):
    """
    Get all IPs for project and associated data: ports, port checks
    """
    ips = await get_ipsdb(project_id, skip, limit, has_ports)
    return ips if ips else []


@ips_router.delete(
    "",
    summary="Delete IPs",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["projects:ips"],
)
async def delete_ips(project_id: str):
    """
    Delete all IPs in project with associated data: ports, port checks
    """
    result = await delete_ipsdb(project_id)
    if result is None:
        raise HTTPException(
            status_code=404, 
            detail=Message.IPS_CANNOT_DELETE
        )


@ips_router.post(
    "",
    summary="Create IP(s)",
    tags=["projects:ips"],
    response_model=List[str]
)
async def create_ip(
    project_id: str, 
    new_ips: Annotated[List[IPIn], Body(),],
    mode: ImportMode = "insert"
):
    """
    Create new IP(s) in project with associated data
    """
    result = await create_ipsdb(project_id, new_ips, mode)
    if result is None:
        raise HTTPException(
            status_code=400, 
            detail=Message.IPS_CANNOT_ADD
        )
    return result


@ips_router.post(
    "/import",
    summary="Import report",
    tags=["projects:ips"],
    response_model=List[str]
)
async def import_ips(
    project_id: str,
    file: Annotated[str, Depends(file_upload)],
    mode: ImportMode = "insert"
):
    """
    Import report file into project. nmap XML only.
    """
    result = await import_ipsdb(project_id, file, mode)
    if result is None:
        raise HTTPException(
            status_code=400, 
            detail=Message.IPS_CANNOT_IMPORT
        )
    return result


@ips_router.get(
    "/download",
    summary="Download IPs",
    tags=["projects:ips"],
)
async def download_ips(
    project_id: str,
    skip: Annotated[int | None, Query(ge=0)] = None,
    limit: Annotated[int | None, Query(ge=0)] = None,
    has_ports: Annotated[bool, Query()] = True,
    format: DownloadReportFormat = DownloadReportFormat.XML
):
    """
    Download all IPs for project and associated data: ports, port checks
    """
    report = await download_ipsdb_report(project_id, skip, limit, has_ports, format)
    if report is None:
        raise HTTPException(
            status_code=400, 
            detail=Message.IPS_CANNOT_DOWNLOAD_REPORT
        )
    
    if format == DownloadReportFormat.XML:
        return Response(content=report, media_type="application/xml")
    
    return 
    #elif format == DownloadReportFormat.JSON:
    #    return Response(content=report, media_type="application/json")


@ips_router.get(
    "/{ip_address}",
    response_model=IPOut,
    summary="Get IP",
    tags=["projects:ips"],
)
async def get_ip(
    project_id: str,
    ip_address: str,
):
    """
    Get IP by address for project and associated data: ports, port checks
    """
    ip = await get_ipdb(project_id, ip_address)
    if ip is None:
        raise HTTPException(
            status_code=404, 
            detail=Message.IP_NOT_FOUND
        )
    return ip


@ips_router.delete(
    "/{ip_address}",
    summary="Delete IP",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["projects:ips"],
)
async def delete_ip(
    project_id: str,
    ip_address: str,
):
    """
    Delete IP by address for project with associated data: ports, port checks
    """
    result = await delete_ipdb(project_id, ip_address)
    if result is None:
        raise HTTPException(
            status_code=404, 
            detail=Message.IP_NOT_FOUND
        )
    

@ips_router.put(
    "/{ip_address}",
    summary="Update IP",
    tags=["projects:ips"],
    response_model=IPOut,
)
async def update_ip(
    project_id: str,
    ip_address: str,
    ip_data: Annotated[BaseIPIn, Body()],
):
    """
    Update IP by address for project with associated data: ports, port checks
    """
    updated_ipdb = await modify_ipdb(project_id, ip_address, ip_data)
    if updated_ipdb is None:
        raise HTTPException(
            status_code=404, 
            detail=Message.IP_NOT_FOUND
        )
    
    return updated_ipdb