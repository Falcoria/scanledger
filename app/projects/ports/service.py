from typing import List, Union
from .models import PortDB
from .schemas import PortIn, PortToDB

from app.projects.ips.models import IPDB
from app.projects.ips.schemas import IPIn


def port_scheme2model(port: PortIn) -> PortDB:
    port_data = port.model_dump(exclude_unset=True)
    return PortDB(**port_data)