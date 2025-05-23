import uuid
#import ipaddress

from pydantic import BaseModel, Field, field_validator
from typing import List, Optional
from datetime import date
from enum import Enum

class ProjectBase(BaseModel):
    #start_date: Optional[date]
    #end_date: Optional[date]
    #users: List[str] = []
    #scope: Optional[Scope] = None
    comment: Optional[str] = None
    pass


class ProjectName(BaseModel):
    project_name: str


class ProjectIn(ProjectBase):
    project_name: str = Field(max_length=30, pattern='^[0-9a-z_A-Z-]+$')


class ProjectOut(ProjectBase, ProjectName):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    users: List[str] = []
    
    @field_validator('users', mode='before')
    def set_users(cls, value, values):
        if value:
            return [user.username for user in value]
        else:
            return []
