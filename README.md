# ScanLedger

ScanLedger is the backend database and API layer of the Falcoryon system. It manages scanned IPs, ports, hostnames, and service checks, storing only actionable results (e.g., open ports).

## Features

- Declarative "scanner-as-code" design.
- Supports import modes: insert, update, replace, append.
- API and CLI integration.
- Stores only open ports by design.
- Export support: XML, JSON, CSV (planned).
- Modular structure for projects, IPs, ports, and hostnames.
- Designed for distributed scanning and chaining phases.

## Usage

ScanLedger is intended to be used together with the `falc.py` CLI tool to initiate scans, import results, and manage scan data efficiently.

## License

MIT
# scan-ledger
