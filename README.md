# ScanLedger

ScanLedger is the shared state database in the [Falcoria](https://github.com/Falcoria/falcoria) distributed scanning system. Every scan result — whether from a Falcoria worker or an imported Nmap report — gets merged into ScanLedger according to the chosen import mode.

Data is organized by project. Each project maintains unique records per IP, port, and hostname. When new data comes in, it doesn't overwrite the previous state blindly — the import mode (insert, append, update, replace) controls what happens to existing records.

ScanLedger also tracks change history: if a port state, service, or banner changes between scans, the transition is recorded.

## Quick start

The fastest way to run everything (ScanLedger + Tasker + Worker + Postgres + Redis + RabbitMQ):

```bash
git clone https://github.com/Falcoria/falcoria.git
cd falcoria
./quickstart.sh
```

See the [all-in-one repo](https://github.com/Falcoria/falcoria) for details.

## Standalone setup

If you're deploying ScanLedger separately (distributed setup or data aggregation only):

```bash
git clone https://github.com/Falcoria/scanledger.git
cd scanledger
./quickstart.sh
```

The script generates TLS certificates, creates `.env` from the example, sets random credentials, starts services with Docker Compose, and prints the admin token.

ScanLedger runs on port `443` (HTTPS). API docs are available at `/docs`.

### Manual setup (development)

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # edit database and token settings
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Requires a running PostgreSQL instance.

## Configuration

Environment variables in `.env`:

- `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_HOST` — database connection
- `ADMIN_TOKEN` — token for falcli and admin API endpoints
- `TASKER_TOKEN` — token for Tasker integration

## Usage

ScanLedger is accessed through [falcli](https://github.com/Falcoria/falcli) or the REST API directly. Common operations:

```bash
# Import a report
falcli project ips import -f report.xml --mode append

# View current state
falcli project ips get

# View change history
falcli project ips history

# Export as Nmap XML
falcli project ips download
```

## Documentation

Full documentation: [https://falcoria.github.io/falcoria-docs/](https://falcoria.github.io/falcoria-docs/)

- [Architecture](https://falcoria.github.io/falcoria-docs/architecture/) — how ScanLedger fits into the system
- [Import Modes](https://falcoria.github.io/falcoria-docs/concepts/import-modes/) — how scan data is merged
- [Change History](https://falcoria.github.io/falcoria-docs/concepts/change-history/) — what gets tracked between scans

## License

MIT. See [LICENSE.md](LICENSE.md).
