import re
from typing import Optional, Dict, List
from ipaddress import ip_address

from app.projects.ips.schemas import IPIn
from app.projects.ports.schemas import PortIn

from falcoria_common.schemas.enums.port import ProtocolEnum

from .schemas import Port, Script, Host, NmapReport


class NmapToInternal:
    @staticmethod
    def extract_requested_ports(nmap_args: str, fallback_services: Optional[str] = None) -> List[int]:
        match = re.search(r"-p\s*([^\s]+)", nmap_args)
        port_expr = match.group(1) if match else fallback_services
        if not port_expr:
            return []

        if port_expr.strip() == "-":
            return list(range(1, 65536))

        result = []
        for part in port_expr.split(","):
            if "-" in part:
                try:
                    start, end = map(int, part.split("-"))
                    if start <= end:
                        result.extend(range(start, end + 1))
                except ValueError:
                    continue
            else:
                try:
                    result.append(int(part))
                except ValueError:
                    continue
        return result

    @staticmethod
    def extract_protocol(nmap_args: str) -> ProtocolEnum:
        if "-sU" in nmap_args:
            return ProtocolEnum.udp
        return ProtocolEnum.tcp

    @staticmethod
    def port_to_portin(port: Port) -> PortIn:
        service = port.service

        return PortIn(
            number=port.portid,
            protocol=ProtocolEnum(port.protocol),
            state=port.state.state,
            reason=port.state.reason,
            service=service.name if service and service.name else "",
            product=service.product if service and service.product else "",
            version=service.version if service and service.version else None,
            extrainfo=service.extrainfo if service and service.extrainfo else None,
            cpe=service.cpe if service and service.cpe else [],
            servicefp=service.servicefp if service and service.servicefp else None,
            scripts=NmapToInternal._scripts_to_dict(port.scripts),
        )

    @staticmethod
    def _scripts_to_dict(scripts: Optional[List[Script]]) -> Dict[str, str]:
        return {s.id: s.output for s in scripts} if scripts else {}

    @staticmethod
    def host_to_ipin(host: Host, requested_ports: List[int], protocol: ProtocolEnum) -> IPIn:
        return IPIn(
            ip=str(ip_address(host.address.addr)),
            status=host.status.state,
            starttime=host.starttime,
            endtime=host.endtime,
            os=NmapToInternal._extract_os_name(host),
            hostnames=host.hostnames or [],
            ports=[NmapToInternal.port_to_portin(p) for p in host.ports.ports],
            not_shown_ports=NmapToInternal._extract_not_shown_ports(host, requested_ports),
            not_shown_ports_protocol=protocol
        )

    @staticmethod
    def _extract_os_name(host: Host) -> str:
        if host.os and host.os.matches:
            return host.os.matches[0].name
        return ""

    @staticmethod
    def _extract_not_shown_ports(host: Host, requested_ports: List[int]) -> List[int]:
        shown_ports = {p.portid for p in host.ports.ports}
        return sorted(set(requested_ports) - shown_ports)

    @staticmethod
    def report_to_ipins(report: NmapReport) -> List[IPIn]:
        requested_ports = NmapToInternal.extract_requested_ports(
            report.args, fallback_services=report.scaninfo.services
        )
        protocol = NmapToInternal.extract_protocol(report.args)
        return [
            NmapToInternal.host_to_ipin(host, requested_ports, protocol)
            for host in report.hosts
        ]
