from datetime import datetime, timezone
from typing import Optional, List
from enum import Enum
from ipaddress import ip_address

from pydantic import BaseModel, Field, field_validator, model_validator

from app.projects.ports.schemas import PortIn, PortState, PortOut


class ImportMode(str, Enum):
    INSERT = "insert"
    REPLACE = "replace"
    UPDATE = "update"
    APPEND = "append"


class DownloadReportFormat(str, Enum):
    #JSON = "json"
    #CSV = "csv"
    XML = "xml"

class BaseIPIn(BaseModel):
    asnName: Optional[str] = ""
    orgName: Optional[str] = ""
    # New fields from xml2json:
    status: Optional[str] = ""
    os: Optional[str] = ""
    endtime: Optional[int] = 0
    hostnames: Optional[List[str]] = []
    ports: Optional[List[PortIn]] = []


class IPAddress(BaseModel):
    ip: Optional[str]


class IPIn(BaseIPIn, IPAddress):

    @model_validator(mode="before")
    def filter_invalid_ports(cls, values):
        """
        Filters out ports with states not listed in the PortState enum.
        Only keeps ports where state == "open".
        """
        ports = values.get('ports', [])
        if isinstance(ports, list):
            values['ports'] = [p for p in ports if p.get('state') == PortState.open.value]
        return values

    @field_validator('ip', mode="before")
    def validate_ip(cls, v):
        if v is None:
            return v
        try:
            return str(ip_address(v))
        except ValueError:
            raise ValueError('Invalid IP address')


class IPOut(BaseIPIn, IPAddress):
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


class IPOutNmap(BaseIPIn, IPAddress):
    class Config:
        fields = {
            "asnName": {"exclude": True},
            "orgName": {"exclude": True},
        }