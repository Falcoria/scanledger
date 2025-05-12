from pydantic import BaseModel, validator
from typing import Optional, List
from enum import Enum


#from app.projects.urls.schemas import UrlObjIn, UrlObjOut


class ImportMode(str, Enum):
    INSERT  = "insert"
    REPLACE = "replace"


class HostToolsEnum(str, Enum):
    SUBFINDER = "subfinder"


class HostBase(BaseModel):
    description: Optional[str]
    ips: Optional[List[str]]
    #urls: Optional[List[UrlObjIn]]


class HostName(BaseModel):
    hostname: str


class HostIn(HostBase, HostName):
    pass


class HostOut(HostBase, HostName):
    #urls: Optional[List[UrlObjOut]]
    @validator('ips', pre=True, always=True)
    def set_ips(cls, v, values):
        if v:
            return [ip.ip for ip in v]
        else:
            return []