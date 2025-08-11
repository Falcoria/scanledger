from falcoria_common.schemas.port import Port

#from app.projects.port_checks.schemas import PortCheckIn, PortCheckOut
#from app.projects.port_checks.models import PortCheckDB

class PortIn(Port):
    """Input schema for a scanned port"""
    pass


class PortOut(Port):
    """ Class for outcoming Port object """
    pass