from typing import Optional, List, Literal
from enum import Enum
from ipaddress import ip_address

from pydantic import BaseModel, Field, field_validator, model_validator

from app.projects.ports.schemas import PortIn, PortOut
from app.projects.filters import FilterOp, FilterConfig

from falcoria_common.schemas.enums.port import ProtocolEnum, PortState
from falcoria_common.schemas.ips import BaseIP


class DownloadReportFormat(str, Enum):
    JSON = "json"
    XML = "xml"


def validate_ip_address(v: str | None) -> str | None:
    if v is None:
        return v
    try:
        return str(ip_address(v))
    except ValueError:
        raise ValueError(f"Invalid IP address: {v}")


class BaseIPIn(BaseIP):
    ports: Optional[List[PortIn]] = []


class IPAddress(BaseModel):
    ip: Optional[str]


class IPIn(BaseIPIn, IPAddress):
    not_shown_ports: Optional[List[int]] = Field(
        default_factory=list,
        description="Ports that were scanned and reported as not open (e.g., closed/filtered) but not shown in the Nmap report."
    )
    not_shown_ports_protocol: Optional[ProtocolEnum] = Field(
        default=ProtocolEnum.tcp,
        description="Protocol of the not shown ports, if applicable."
    )

    @field_validator('ip', mode="before")
    def validate_ip(cls, v):
        return validate_ip_address(v)


class IPDeleteRequest(BaseModel):
    ip_addresses: List[str]

    @field_validator('ip_addresses', mode="before")
    def validate_ips(cls, v):
        return [validate_ip_address(addr) for addr in v]


class IPOut(BaseIP, IPAddress):
    ports: Optional[List[PortOut]]

    @field_validator('hostnames', mode="before")
    def set_hostnames(cls, v):
        if v:
            return [host.hostname for host in v]
        return []

    @model_validator(mode="after")
    def sort_ports(cls, values):
        if values.ports:
            values.ports.sort(key=lambda p: p.number)
        return values


class IPOutNmap(BaseIP, IPAddress):
    def to_nmap_json(self):
        # Return a dict representation suitable for Nmap JSON
        return self.model_dump(exclude_none=True)

    class Config:
        fields = {
            "asnName": {"exclude": True},
            "orgName": {"exclude": True},
        }


IPFilterField = Literal["ip", "hostname", "port", "protocol", "state", "service", "product"]


class FilterModel(str, Enum):
    IP = "ip"
    PORT = "port"
    HOST = "host"


class IpsFilterConfig(FilterConfig):
    """Extends FilterConfig with target table (model) for IP-related filters."""
    model: FilterModel


class PortsMode(str, Enum):
    ALL = "all"
    MATCHED = "matched"


class IPFilterParams(BaseModel):
    """Query filter parameters for IP listing endpoint."""
    ip: Optional[str] = None
    hostname: Optional[str] = None
    port: Optional[int] = Field(default=None, ge=0, le=65535)
    protocol: Optional[ProtocolEnum] = None
    state: Optional[PortState] = None
    service: Optional[str] = None
    product: Optional[str] = None
    ports_mode: PortsMode = PortsMode.ALL


FILTER_CONFIG: dict[IPFilterField, IpsFilterConfig] = {
    "ip":       IpsFilterConfig(op=FilterOp.PREFIX, model=FilterModel.IP,   field="ip"),
    "hostname": IpsFilterConfig(op=FilterOp.ILIKE,  model=FilterModel.HOST, field="hostname"),
    "port":     IpsFilterConfig(op=FilterOp.EXACT,  model=FilterModel.PORT, field="number"),
    "protocol": IpsFilterConfig(op=FilterOp.EXACT,  model=FilterModel.PORT, field="protocol"),
    "state":    IpsFilterConfig(op=FilterOp.EXACT,  model=FilterModel.PORT, field="state"),
    "service":  IpsFilterConfig(op=FilterOp.ILIKE,  model=FilterModel.PORT, field="service"),
    "product":  IpsFilterConfig(op=FilterOp.ILIKE,  model=FilterModel.PORT, field="product"),
}

assert set(FILTER_CONFIG.keys()) == set(IPFilterParams.model_fields.keys()) - {"ports_mode"}