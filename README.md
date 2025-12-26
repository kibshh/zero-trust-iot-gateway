# Zero-Trust IoT Gateway

A Zero-Trust IoT Device Authorization Gateway implemented on ESP32. The ESP32 acts as a Security Enforcement Point (SEP) between untrusted edge devices and a backend system, enforcing explicit authorization policies at the edge.

## Overview

This project demonstrates:
- Zero-trust principles with explicit authorization
- Edge-enforced security with fail-closed behavior
- Deterministic behavior under failure conditions
- Production-grade embedded security architecture

The ESP32 is the single enforcement point in the system. All device actions (READ / WRITE / COMMAND) must pass through the ESP32 and be explicitly authorized.

## Python Tooling Setup

This project uses Python tooling for build scripts, testing, and helper utilities. Python is **not** used for runtime logic.

### Prerequisites

- Python 3.11 or higher (up to 3.13)
- [uv](https://github.com/astral-sh/uv) package manager (recommended)
- [PlatformIO Core](https://platformio.org/) (installed globally, not in venv)

### Installing PlatformIO

PlatformIO is required to build the ESP32 firmware.

On modern Linux distributions (PEP 668), the recommended way is to install PlatformIO using pipx:

```bash
sudo apt install pipx
pipx ensurepath
pipx install platformio
```

Verify installation:
```bash
pio --version
```

### Installation

1. **Install uv** (one-time setup):
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```
   Or using pip:
   ```bash
   pip install uv
   ```

2. **Clone the repository**:
   ```bash
   git clone <repo-url>
   cd zero_trust_iot_gateway
   ```

3. **Install dependencies**:
   ```bash
   uv sync --dev
   ```
   This command:
   - Creates a virtual environment in `.venv/`
   - Installs all project dependencies
   - Installs development dependencies (pytest, ruff, cryptography)
   - Creates/updates `uv.lock` for reproducible builds

4. **Activate the virtual environment** (if needed for manual commands):
   ```bash
   source .venv/bin/activate  # Linux/macOS
   # or
   .venv\Scripts\activate     # Windows
   ```

### Running Tools

With `uv`, you can run tools directly without activating the venv:

```bash
# Run tests
uv run pytest

# Run linter
uv run ruff check .

# Run formatter
uv run ruff format .

# Run any Python script
uv run python tools/your_script.py
```

Or activate the venv and run tools directly:

```bash
source .venv/bin/activate
pytest
ruff check .
```

## Development

### Adding Dependencies

To add a new Python dependency:

```bash
# Add a runtime dependency
uv add package-name

# Add a development dependency
uv add --dev package-name
```

This automatically updates `pyproject.toml` and `uv.lock`.

### Lock File

The `uv.lock` file ensures reproducible builds. **Commit it to version control** so all developers use the same dependency versions.

## License

MIT

