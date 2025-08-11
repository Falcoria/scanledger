from pydantic import BaseModel
from typing import List, Optional

from falcoria_common.schemas.enums.port import PortState


# --- Scan root elements ---
class ScanInfo(BaseModel):
    """Scan Root element"""
    type: str
    protocol: str
    numservices: int
    services: str


class Verbose(BaseModel):
    """Scan Root element"""
    level: int


class Debugging(BaseModel):
    """Scan Root element"""
    level: int


class TaskProgress(BaseModel):
    """Scan Root element"""
    task: str
    time: int
    percent: float
    remaining: Optional[int]
    etc: Optional[int]


# --- Host elements ---
class Status(BaseModel):
    """Host element"""
    state: str
    reason: str
    reason_ttl: int


class Address(BaseModel):
    """Host element"""
    addr: str
    addrtype: str


# --- Ports and related ---
class ExtraReasons(BaseModel):
    reason: str
    count: int


class ExtraPorts(BaseModel):
    state: str
    count: int
    extrareasons: List[ExtraReasons] = []


class PortStatus(BaseModel):
    """Port element"""
    state: PortState
    reason: str
    reason_ttl: int


class ScriptElem(BaseModel):
    key: str
    text: str


class Script(BaseModel):
    id: str
    output: str
    elems: List[ScriptElem] = []


class Service(BaseModel):
    name: Optional[str]
    product: Optional[str]
    version: Optional[str]
    extrainfo: Optional[str]
    ostype: Optional[str]
    method: Optional[str]
    conf: Optional[int]
    cpe: List[str] = []
    servicefp: Optional[str]


class Port(BaseModel):
    """Port element"""
    protocol: str
    portid: int
    state: PortStatus
    service: Optional[Service] = None
    scripts: List[Script] = []


class Ports(BaseModel):
    """Host element"""
    ports: List[Port]
    extraports: List[ExtraPorts] = []


# --- OS detection ---
class OSClass(BaseModel):
    type: Optional[str]
    vendor: Optional[str]
    osfamily: Optional[str]
    osgen: Optional[str]
    accuracy: Optional[int]
    cpe: List[str] = []


class OSMatch(BaseModel):
    name: str
    accuracy: int
    line: Optional[int]
    osclasses: List[OSClass] = []


class OS(BaseModel):
    portused: List[dict] = []
    matches: List[OSMatch] = []


# --- Uptime ---
class Uptime(BaseModel):
    seconds: int
    lastboot: str


# --- Host wrapper ---
class Host(BaseModel):
    """Host element"""
    starttime: int
    endtime: int
    status: Status
    address: Address
    ports: Ports
    os: Optional[OS] = None
    uptime: Optional[Uptime] = None
    hostnames: List[str] = []


# --- Root report element ---
class NmapReport(BaseModel):
    scanner: str
    args: str
    start: int
    startstr: str
    version: str
    xmloutputversion: str
    scaninfo: ScanInfo
    verbose: Verbose
    debugging: Debugging
    taskprogress: Optional[TaskProgress]
    hosts: List[Host] = []  # List of Host objects
