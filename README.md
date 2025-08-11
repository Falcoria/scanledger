# ScanLedger

ScanLedger is a structured scan result database used as part of the Falcoria distributed scanning system. It stores information about discovered IPs, ports, services, and banners from Nmap and other tools. The database supports controlled import and merging of scan data using flexible import modes.

## Features

- Supports import modes: insert, update, replace, append
- API and CLI integration
- Export support: XML, JSON, CSV
- Modular structure for projects, IPs, ports, and hostnames
- Designed for distributed scanning and chaining phases

The power of ScanLedger comes from its flexible import modes, which allow you to control how scan data is merged, updated, or replaced.

You can explore real-world examples here:

- [Import Modes](https://falcoria.github.io/falcoria-docs/import-modes/)
- [Use Cases](https://falcoria.github.io/falcoria-docs/use-cases/)

## Usage

ScanLedger is intended to be used together with the `falcli.py` CLI tool to initiate scans, import results, and manage scan data efficiently.

## Installation

### 1. Virtual Environment (for development)

Ensure PostgreSQL is running and accessible.

```bash
# Clone repository
git clone https://github.com/Falcoria/scanledger.git
cd scanledger

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Configure environment
cp .env.example .env
nano .env  # Edit database and tokens

# Run app
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

API is available at `https://localhost:8000`, with docs at `/docs`.

---

### 2. Docker (with TLS)

Before running the container, generate self-signed TLS certificates:

```bash
./generate-tls-bundle.sh
```

Then run the Docker container:

```bash
docker run -d \
  --name scanledger \
  -p 443:443 \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=changeme \
  -e POSTGRES_DB=falcoriadb \
  -e POSTGRES_HOST=localhost \
  -e ENVIRONMENT=development \
  -e ADMIN_TOKEN=changeme \
  -e TASKER_TOKEN=changeme \
  -v $(pwd)/unit/bundle.pem:/docker-entrypoint.d/bundle.pem:ro \
  ghcr.io/falcoria/scanledger:latest
```

Ensure PostgreSQL is running and accessible from within the container.

---

### 3. Docker (build locally)

To build the Docker image locally from the Dockerfile:

```bash
# Clone repository
git clone https://github.com/yourname/scanledger.git
cd scanledger

# Generate self-signed TLS certificates
./generate-tls-bundle.sh

# Build the Docker image
docker build -t scanledger .

# Run the container with environment variables and mounted TLS bundle
docker run -d \
  --name scanledger \
  -p 443:443 \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=changeme \
  -e POSTGRES_DB=falcoriadb \
  -e POSTGRES_HOST=localhost \
  -e ENVIRONMENT=development \
  -e ADMIN_TOKEN=changeme \
  -e TASKER_TOKEN=changeme \
  -v $(pwd)/unit/bundle.pem:/docker-entrypoint.d/bundle.pem:ro \
  scanledger
```

This allows you to test or develop locally without pulling from GitHub Container Registry.

---

## Running ScanLedger with Docker Compose

To run ScanLedger with a built-in PostgreSQL database using Docker Compose, follow these steps:

### 1. Clone the repository

```bash
git clone https://github.com/your-org/scanledger.git
cd scanledger
```

### 2. Create a `.env` file

Define the following variables in your `.env` file:

```env
POSTGRES_DB=scanledger
POSTGRES_USER=scanledger_user
POSTGRES_PASSWORD=supersecure
```

These values will be used to configure the PostgreSQL service.

### 3. Start services

Use Docker Compose to build and start all services:

```bash
docker compose up --build
```

This command launches:
- `scanledger` service, served on port 443
- `postgres` service, using a persistent volume

### 4. Access the application

After the services start successfully, access ScanLedger via HTTPS on:

```
https://localhost:443
```

Make sure you have valid certificates in place (such as `bundle.pem`) as configured in your Compose setup.

---

## Example API Request

Once ScanLedger is running, you can use a tool like `curl` to interact with the API. For example, to import a scan file:

```bash
curl -X POST https://localhost:443/projects \
  -H "Authorization: Bearer <YOUR_ADMIN_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"project_name": "example-project", "comment": "Initial test project"}' \
  --insecure
```

Alternatively, you can use the falcli command-line tool for more convenient access:
[falcli command-line tool](https://github.com/Falcoria/falcli)

```bash
python3 falcli.py project create example-project
```

You can browse available endpoints and parameters at:

```
https://localhost:443/docs
```

---

## License

This project is licensed under the MIT License. See the [LICENSE.md](LICENSE.md) file for details.
