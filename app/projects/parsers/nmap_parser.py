import json
from libnmap.parser import NmapParser


class NmapDataFormatter:
    def __init__(self):
        pass

    @staticmethod
    def parse_xmlfile_report(xml_report):
        try:
            data_report = NmapParser.parse_fromfile(xml_report)
            return data_report
        except Exception as e:
            print(f"Cannot read xml nmap file report!: {e}")
            return None

    @staticmethod
    def parse_xmlstring_report(xml_report):
        try:
            data_report = NmapParser.parse_fromstring(xml_report)
            return data_report
        except Exception as e:
            print(f"Cannot read xml nmap string report! {e}")
            return None

    @staticmethod
    def xml2json(formatted_report):
        def _expand_port_ranges(portlist: str):
            ports = []
            for part in portlist.split(","):
                if "-" in part:
                    lo, hi = map(int, part.split("-"))
                    ports.extend(range(lo, hi + 1))
                else:
                    ports.append(int(part))
            return ports

        results = []
        for host in formatted_report.hosts:
            result = dict()
            result["ip"] = host.ipv4
            result["date"] = host.endtime
            result["hostnames"] = host.hostnames
            result["ports"] = list()
            result["status"] = host.status
            result["endtime"] = host.endtime
            osmatch = host.os.osmatch()
            result["os"] = osmatch[0] if osmatch else ""

            for service in host.services:
                port_dict = dict()
                port_dict["number"] = service.port
                port_dict["protocol"] = service.protocol
                port_dict["state"] = service.state
                port_dict["banner"] = service.banner
                port_dict["service"] = service.service
                port_dict["servicefp"] = service.servicefp
                j = [json.dumps(sr) for sr in service.scripts_results]
                port_dict["scripts"] = " ".join(j)

                if service.reason:
                    port_dict["reason"] = service.reason

                result["ports"].append(port_dict)

            # Add extraports not listed in host.services
            extras = host._extras.get("ports", {})
            extraports = extras.get("extraports", [])
            if not isinstance(extraports, list):
                extraports = [extraports]

            existing_ports = {s.port for s in host.services}

            for ep in extraports:
                ep_state = ep.get("@state")
                ep_reason = ep.get("extrareasons", {}).get("@reason")
                ports_str = ep.get("extrareasons", {}).get("@ports", "")
                if not ports_str:
                    continue

                expanded = _expand_port_ranges(ports_str)

                for port in expanded:
                    if port in existing_ports:
                        continue
                    port_dict = {
                        "number": port,
                        "protocol": "tcp",
                        "state": ep_state,
                        "reason": ep_reason,
                        "banner": "",
                        "service": "",
                        "servicefp": "",
                        "scripts": ""
                    }
                    result["ports"].append(port_dict)

            results.append(result)
        return results

    @staticmethod
    def xmlfile2json(xml_report):
        formatted_report = NmapDataFormatter.parse_xmlfile_report(xml_report)
        if not formatted_report:
            return None
        return NmapDataFormatter.xml2json(formatted_report)


    @staticmethod
    def xmlstring2json(xml_report):
        formatted_report = NmapDataFormatter.parse_xmlstring_report(xml_report)
        if not formatted_report:
            return None
        return NmapDataFormatter.xml2json(formatted_report)