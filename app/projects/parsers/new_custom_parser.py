import json
import xml.etree.ElementTree as ET

from pathlib import Path
from typing import Optional, List

from .schemas import (
    NmapReport,
    ScanInfo,
    Verbose,
    Debugging,
    TaskProgress,
    Host,
    Status,
    Address,
    Port,
    PortStatus,
    Ports,
    PortState,
    Service,
    Script,
    ScriptElem,
    OS,
    OSMatch,
    OSClass,
    Uptime,
    ExtraPorts,
    ExtraReasons
)



class NmapParser:
    def __init__(self):
        self.root = None

    def _parse_xml(self, file_path: str):
        tree = ET.parse(file_path)
        return tree.getroot()

    def parse(self) -> NmapReport:
        root = self.root

        return NmapReport(
            scanner=root.attrib["scanner"],
            args=root.attrib["args"],
            start=int(root.attrib["start"]),
            startstr=root.attrib["startstr"],
            version=root.attrib["version"],
            xmloutputversion=root.attrib["xmloutputversion"],
            scaninfo=self._parse_scaninfo(root.find("scaninfo")),
            verbose=self._parse_verbose(root.find("verbose")),
            debugging=self._parse_debugging(root.find("debugging")),
            taskprogress=self._parse_taskprogress(root.find("taskprogress")),
            hosts=[self._parse_host(h) for h in root.findall("host")]
        )

    def _parse_scaninfo(self, el):
        return ScanInfo(
            type=el.attrib["type"],
            protocol=el.attrib["protocol"],
            numservices=int(el.attrib["numservices"]),
            services=el.attrib["services"]
        )

    def _parse_verbose(self, el):
        return Verbose(level=int(el.attrib["level"]))

    def _parse_debugging(self, el):
        return Debugging(level=int(el.attrib["level"]))

    def _parse_taskprogress(self, el):
        if el is None:
            return None
        return TaskProgress(
            task=el.attrib["task"],
            time=int(el.attrib["time"]),
            percent=float(el.attrib["percent"]),
            remaining=int(el.attrib["remaining"]) if "remaining" in el.attrib else None,
            etc=int(el.attrib["etc"]) if "etc" in el.attrib else None
        )

    def _parse_host(self, el) -> Host:
        status_el = el.find("status")
        address_el = el.find("address")
        hostnames_el = el.find("hostnames")

        hostnames = []
        if hostnames_el is not None:
            hostnames = [hn.attrib["name"] for hn in hostnames_el.findall("hostname") if "name" in hn.attrib]

        return Host(
            starttime=int(el.attrib["starttime"]),
            endtime=int(el.attrib["endtime"]),
            status=Status(
                state=status_el.attrib["state"],
                reason=status_el.attrib["reason"],
                reason_ttl=int(status_el.attrib["reason_ttl"])
            ),
            address=Address(
                addr=address_el.attrib["addr"],
                addrtype=address_el.attrib["addrtype"]
            ),
            ports=self._parse_ports(el.find("ports")),
            os=self._parse_os(el.find("os")),
            uptime=self._parse_uptime(el.find("uptime")),
            hostnames=hostnames
        )
    
    def _parse_ports(self, el) -> Ports:
        port_elements = el.findall("port")
        ports = []
        for p in port_elements:
            state_el = p.find("state")
            service_el = p.find("service")
            ports.append(Port(
                protocol=p.attrib["protocol"],
                portid=int(p.attrib["portid"]),
                state=PortStatus(
                    state=PortState(state_el.attrib["state"]),
                    reason=state_el.attrib["reason"],
                    reason_ttl=int(state_el.attrib["reason_ttl"])
                ),
                service=self._parse_service(service_el) if service_el is not None else None,
                scripts=self._parse_scripts(p)
            ))
        extraports = self._parse_extraports(el)
        return Ports(ports=ports, extraports=extraports)
    
    def _parse_service(self, el) -> Service:
        cpes = [c.text for c in el.findall("cpe")]
        return Service(
            name=el.attrib.get("name"),
            product=el.attrib.get("product"),
            version=el.attrib.get("version"),
            extrainfo=el.attrib.get("extrainfo"),
            ostype=el.attrib.get("ostype"),
            method=el.attrib.get("method"),
            conf=int(el.attrib["conf"]) if "conf" in el.attrib else None,
            cpe=cpes,
            servicefp=el.attrib.get("servicefp")
        )

    def _parse_scripts(self, port_el) -> list[Script]:
        scripts = []
        for script_el in port_el.findall("script"):
            elems = [
                ScriptElem(key=e.attrib["key"], text=e.text or "")
                for e in script_el.findall("elem")
            ]
            scripts.append(Script(
                id=script_el.attrib["id"],
                output=script_el.attrib["output"],
                elems=elems
            ))
        return scripts
    
    def _parse_os(self, el) -> OS:
        if el is None:
            return None

        portused = [
            {"state": p.attrib["state"], "proto": p.attrib["proto"], "portid": int(p.attrib["portid"])}
            for p in el.findall("portused")
        ]

        matches = []
        for match_el in el.findall("osmatch"):
            osclasses = []
            for c in match_el.findall("osclass"):
                osclasses.append(OSClass(
                    type=c.attrib.get("type"),
                    vendor=c.attrib.get("vendor"),
                    osfamily=c.attrib.get("osfamily"),
                    osgen=c.attrib.get("osgen"),
                    accuracy=int(c.attrib.get("accuracy", "0")),
                    cpe=[e.text for e in c.findall("cpe")]
                ))

            matches.append(OSMatch(
                name=match_el.attrib["name"],
                accuracy=int(match_el.attrib["accuracy"]),
                line=int(match_el.attrib["line"]) if "line" in match_el.attrib else None,
                osclasses=osclasses
            ))

        return OS(portused=portused, matches=matches)
    
    def _parse_uptime(self, el) -> Optional[Uptime]:
        if el is None:
            return None
        return Uptime(
            seconds=int(el.attrib["seconds"]),
            lastboot=el.attrib["lastboot"]
        )

    def _parse_extraports(self, ports_el) -> List[ExtraPorts]:
        result = []
        for ex in ports_el.findall("extraports"):
            reasons = []
            for r in ex.findall("extrareasons"):
                reasons.append(ExtraReasons(
                    reason=r.attrib["reason"],
                    count=int(r.attrib["count"])
                ))
            result.append(ExtraPorts(
                state=ex.attrib["state"],
                count=int(ex.attrib["count"]),
                extrareasons=reasons
            ))
        return result

    
    @classmethod
    def parse_from_string(cls, xml_string: str) -> NmapReport:
        """Parse nmap report from an XML string.
        
        Args:
            xml_string: String containing nmap XML report
            
        Returns:
            Parsed NmapReport object
        """
        parser = cls()
        parser.root = ET.fromstring(xml_string)
        return parser.parse()

    @classmethod
    def parse_from_file(cls, file_path: str) -> NmapReport:
        """Parse nmap report from a file path.
        
        Args:
            file_path: Path to nmap XML report file
            
        Returns:
            Parsed NmapReport object
        """
        parser = cls()
        parser.root = parser._parse_xml(file_path)
        return parser.parse()
