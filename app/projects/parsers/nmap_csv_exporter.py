import csv
import io
from typing import List
from app.projects.ips.models import IPDB

def export_ips_to_csv(ips: List[IPDB]) -> str:
    output = io.StringIO()

    base_fields = ["ip", "status", "hostname", "os"]
    port_fields_set = set()

    # First pass: collect all port fields correctly
    for ip in ips:
        for portdb in ip.ports:
            port = portdb.model_dump(by_alias=True, mode="json")
            for key in port.keys():
                port_fields_set.add(key)

    port_fields = [f"port_{field}" for field in sorted(port_fields_set)]
    fieldnames = base_fields + port_fields

    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for ip in ips:
        host_data = ip.model_dump(by_alias=True, mode="json")
        os_name = host_data.get("os", "")
        status = host_data.get("status", "up")
        hostnames = host_data.get("hostnames", [])
        hostnames = hostnames or [""]

        ports = ip.ports
        if not ports:
            ports = [None]

        for hostname in hostnames:
            for portdb in ports:
                row = {field: "" for field in fieldnames}
                row["ip"] = host_data["ip"]
                row["status"] = status
                row["hostname"] = hostname
                row["os"] = os_name

                if portdb:
                    port = portdb.model_dump(by_alias=True, mode="json")
                    for key, value in port.items():
                        row[f"port_{key}"] = value

                writer.writerow(row)

    return output.getvalue()
