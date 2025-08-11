from typing import Optional, List
from enum import Enum
from ipaddress import ip_address

from pydantic import BaseModel, Field, field_validator, model_validator

from app.projects.ports.schemas import PortIn, PortOut

from falcoria_common.schemas.enums.port import ProtocolEnum
from falcoria_common.schemas.ips import BaseIP


class DownloadReportFormat(str, Enum):
    JSON = "json"
    XML = "xml"


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
        if v is None:
            return v
        try:
            return str(ip_address(v))
        except ValueError:
            raise ValueError('Invalid IP address')


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