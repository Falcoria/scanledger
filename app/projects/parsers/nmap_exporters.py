import json
from typing import List
from datetime import datetime, timezone
import xml.etree.ElementTree as ET

from app.projects.ips.models import IPDB
from app.projects.ports.models import PortDB
from app.projects.ips.schemas import IPOutNmap


def add_service(port_elem, port_data):
    service = ET.SubElement(port_elem, "service")
    service.set("name", port_data.get("service", "") or "")

    banner = port_data.get("banner", "") or ""
    tokens = banner.split()
    product = version = extrainfo = ""

    for idx, token in enumerate(tokens):
        if token.startswith("product:"):
            product = " ".join(tokens[idx + 1:]).split("version:")[0].strip()
        if token.startswith("version:"):
            version = " ".join(tokens[idx + 1:]).split("extrainfo:")[0].strip()
        if token.startswith("extrainfo:"):
            extrainfo = " ".join(tokens[idx + 1:]).strip()

    if product:
        service.set("product", product)
    if version:
        service.set("version", version)
    if extrainfo:
        service.set("extrainfo", extrainfo)


def add_port(ports_elem, portdb: PortDB):
    port = portdb.model_dump(by_alias=True, mode="json")

    port_elem = ET.SubElement(ports_elem, "port")
    port_elem.set("protocol", port["protocol"])
    port_elem.set("portid", str(port["number"]))

    state_elem = ET.SubElement(port_elem, "state")
    state_elem.set("state", port["state"])
    state_elem.set("reason", port.get("reason", "syn-ack"))

    add_service(port_elem, port)


def add_host(nmaprun_elem, ip: IPDB):
    host_data = ip.model_dump(by_alias=True, mode="json")

    host = ET.SubElement(nmaprun_elem, "host")

    status = ET.SubElement(host, "status")
    status.set("state", host_data.get("status", "up"))

    address = ET.SubElement(host, "address")
    address.set("addr", host_data["ip"])
    address.set("addrtype", "ipv4")

    hostnames = ET.SubElement(host, "hostnames")
    for hostname in host_data.get("hostnames", []):
        hn = ET.SubElement(hostnames, "hostname")
        hn.set("name", hostname)
        hn.set("type", "user")

    os_fingerprint = host_data.get("os")
    if os_fingerprint:
        os_elem = ET.SubElement(host, "os")
        osmatch = ET.SubElement(os_elem, "osmatch")
        osmatch.set("name", os_fingerprint)

    host_ports = ip.ports
    if host_ports:
        ports_elem = ET.SubElement(host, "ports")
        for portdb in host_ports:
            add_port(ports_elem, portdb)


def export_ips_to_xml(ips: List[IPDB]) -> str:

    nmaprun = ET.Element("nmaprun")
    nmaprun.set("scanner", "nmap")
    nmaprun.set("args", "imported-scan")
    nmaprun.set("version", "7.94")
    nmaprun.set("xmloutputversion", "1.05")

    ET.SubElement(nmaprun, "verbose").set("level", "0")
    ET.SubElement(nmaprun, "debugging").set("level", "0")

    for ip in ips:
        add_host(nmaprun, ip)

    xml_data = ET.tostring(nmaprun, encoding="utf-8", method="xml").decode()

    timestamp = datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S %Y")
    comment = f"<!-- Nmap 7.94 scan initiated {timestamp} as: nmap -sV -oX report.xml target -->"

    header = '<?xml version="1.0" encoding="UTF-8"?>\n'
    doctype = '<!DOCTYPE nmaprun>\n'
    stylesheet = '<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>\n'

    return f"{header}{doctype}{stylesheet}{comment}\n{xml_data}"


def exports_ips_to_json(ips: List[IPDB]) -> str:
    results = []
    for ip in ips:
        ipnmap = IPOutNmap.model_validate(ip.model_dump())
        ip_data = ip.model_dump(by_alias=True, mode="json")
        ip_data["ports"] = [port.model_dump(by_alias=True, mode="json") for port in ip.ports]
        results.append(ip_data)
    return json.dumps(results, indent=4, default=str)