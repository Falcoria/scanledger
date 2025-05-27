# ScanLedger

ScanLedger is the backend database and API layer of the Falcoria system. It manages scanned IPs, ports, hostnames, and service checks, storing only actionable results (e.g., open ports).

## Features

- Supports import modes: insert, update, replace, append
- API and CLI integration
- Export support: XML, JSON, CSV (planned)
- Modular structure for projects, IPs, ports, and hostnames
- Designed for distributed scanning

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

## License

This project is licensed under the MIT License. See the [LICENSE.md](LICENSE.md) file for details.
