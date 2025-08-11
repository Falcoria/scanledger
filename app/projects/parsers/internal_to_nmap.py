import xml.etree.ElementTree as ET
from typing import List
from app.projects.ips.models import IPDB
from app.projects.ports.models import PortDB
from app.projects.hosts.models import HostDB
from app.projects.ports.schemas import PortIn
from app.projects.ips.schemas import IPIn
from app.projects.parsers.schemas import NmapReport, Host, Ports, Port, Service, Status, Address, OS, OSMatch, OSClass, Uptime, ExtraPorts, ExtraReasons, Verbose, Debugging, ScanInfo, TaskProgress, PortStatus
from falcoria_common.schemas.enums.port import PortState

class InternalToNmapXML:
    @staticmethod
    def build_nmap_report(ipdb_list: List[IPDB]) -> NmapReport:
        # This function builds a NmapReport pydantic model from internal IPDB models
        hosts = []
        for ipdb in ipdb_list:
            host = InternalToNmapXML._ipdb_to_host(ipdb)
            hosts.append(host)
        # Fill in dummy values for scaninfo, verbose, debugging, etc. as needed
        return NmapReport(
            scanner="nmap",
            args="",
            start=0,
            startstr="",
            version="7.94",
            xmloutputversion="1.04",
            scaninfo=ScanInfo(type="syn", protocol="tcp", numservices=1000, services="1-65535"),
            verbose=Verbose(level=0),
            debugging=Debugging(level=0),
            taskprogress=None,
            hosts=hosts
        )

    @staticmethod
    def _ipdb_to_host(ipdb: IPDB) -> Host:
        # Convert IPDB to Host
        status = Status(state="up", reason="syn-ack", reason_ttl=0)
        address = Address(addr=ipdb.ip or "", addrtype="ipv4")
        hostnames = [h.hostname or "" for h in (ipdb.hostnames or []) if h and getattr(h, "hostname", None) is not None]
        ports = InternalToNmapXML._ports_to_ports(ipdb.ports or [])
        os = None
        uptime = None
        return Host(
            starttime=ipdb.starttime or 0,
            endtime=ipdb.endtime or 0,
            status=status,
            address=address,
            ports=ports,
            os=os,
            uptime=uptime,
            hostnames=hostnames
        )

    @staticmethod
    def _ports_to_ports(portdb_list: List[PortDB]) -> Ports:
        ports = []
        for portdb in portdb_list or []:
            port = InternalToNmapXML._portdb_to_port(portdb)
            ports.append(port)
        return Ports(ports=ports, extraports=[])

    @staticmethod
    def _portdb_to_port(portdb: PortDB) -> Port:
        state = PortState(portdb.state) if hasattr(portdb, "state") and portdb.state is not None else PortState.open
        port_status = PortStatus(state=state, reason=getattr(portdb, "reason", "") or "", reason_ttl=0)
        cpe_list = getattr(portdb, "cpe", []) or []
        service = Service(
            name=getattr(portdb, "service", None),
            product=getattr(portdb, "product", None),
            version=getattr(portdb, "version", None),
            extrainfo=getattr(portdb, "extrainfo", None),
            ostype=None,
            method=None,
            conf=None,
            cpe=cpe_list,
            servicefp=getattr(portdb, "servicefp", None)
        )
        return Port(
            protocol=getattr(portdb, "protocol", "tcp"),
            portid=getattr(portdb, "number", 0),
            state=port_status,
            service=service,
            scripts=[]
        )

    @staticmethod
    def to_xml(report: NmapReport) -> str:
        # Serialize NmapReport pydantic model to XML string
        # For brevity, use pydantic's .model_dump() and build XML manually
        # This can be expanded for full fidelity
        root = ET.Element("nmaprun", attrib={
            "scanner": report.scanner,
            "args": report.args,
            "start": str(report.start),
            "startstr": report.startstr,
            "version": report.version,
            "xmloutputversion": report.xmloutputversion
        })
        # Add hosts
        for host in report.hosts:
            host_el = ET.SubElement(root, "host")
            ET.SubElement(host_el, "status", state=host.status.state, reason=host.status.reason, reason_ttl=str(host.status.reason_ttl))
            ET.SubElement(host_el, "address", addr=host.address.addr, addrtype=host.address.addrtype)
            if host.hostnames:
                hostnames_el = ET.SubElement(host_el, "hostnames")
                for hn in host.hostnames:
                    ET.SubElement(hostnames_el, "hostname", name=hn)
            ports_el = ET.SubElement(host_el, "ports")
            for port in host.ports.ports:
                port_el = ET.SubElement(ports_el, "port", protocol=port.protocol, portid=str(port.portid))
                ET.SubElement(port_el, "state", state=port.state.state.value, reason=port.state.reason, reason_ttl=str(port.state.reason_ttl))
                if port.service:
                    service_el = ET.SubElement(port_el, "service")
                    if port.service.name:
                        service_el.set("name", port.service.name)
                    if port.service.product:
                        service_el.set("product", port.service.product)
                    if port.service.version:
                        service_el.set("version", port.service.version)
                    if port.service.extrainfo:
                        service_el.set("extrainfo", port.service.extrainfo)
                    if port.service.cpe:
                        for cpe in port.service.cpe:
                            ET.SubElement(service_el, "cpe").text = cpe
        # Return XML string
        return ET.tostring(root, encoding="unicode")
