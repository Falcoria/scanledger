from enum import Enum
from pydantic import BaseModel, Field
from typing import Optional, List

#from app.projects.port_checks.schemas import PortCheckIn, PortCheckOut
#from app.projects.port_checks.models import PortCheckDB


class ProtocolEnum(str, Enum):
    tcp = "tcp"
    udp = "udp"


class PortState(str, Enum):
    open = "open"
    closed = "closed"
    filtered = "filtered"
    unfiltered = "unfiltered"
    open_filtered = "open|filtered"
    closed_filtered = "closed|filtered"


class HTTPServices(Enum):
    HTTP = "http"
    HTTPS = "https"
    HTTPS_ALT = "https-alt"

    @classmethod
    def values(cls):
        return [http_service.value for http_service in cls]


#class PortOutChecks(BaseModel):
#    checks: Optional[List[PortCheckOut]] = []


class PortBase(BaseModel):
    protocol: ProtocolEnum = "tcp"
    state: PortState = "open"
    reason: Optional[str] = ""
    banner: Optional[str] = ""
    service: Optional[str] = ""
    servicefp: Optional[str] = ""
    scripts: Optional[str] = ""


class PortNumber(BaseModel):
    number: int = Field(
        ge=0, le=65535, description="The port number, ranging from 0 to 65535."
    )


#class PortIn(PortInChecks, PortBase, PortNumber):
#    """ Class for incoming Port object """
#    pass

class PortIn(PortBase, PortNumber):
    """ Class for incoming Port object """
    pass


#class PortOut(PortOutChecks, PortBase, PortNumber):
#    """ Class for outcoming Port object """
#    pass

class PortOut(PortBase, PortNumber):
    """ Class for outcoming Port object """
    pass


class PortToDB(PortIn):
    pass
    #checks: Optional[List[PortCheckDB]] = []
