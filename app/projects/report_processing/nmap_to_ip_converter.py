from app.projects.parsers.nmap_parser import NmapDataFormatter
from app.projects.utils import merge_dicts_in_list

def nmap_report_to_ipdict(scan_report: str):
    """
    Convert an Nmap scan report (XML string) to a list of dictionaries
    ready for database insertion (IPs and ports).
    """
    json_report = NmapDataFormatter.xmlstring2json(scan_report)
    if json_report is not None:
        filtered_report = merge_dicts_in_list(json_report, "ip")
        return filtered_report

    return None
