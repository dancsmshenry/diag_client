# diag_client

A small DoIP (ISO 13400-2) / UDS diagnostic client written in Python.

## Project layout

```text
diag_client/
├── diag_client/           # importable package
│   ├── __init__.py
│   ├── doip_config.py     # DoIP entity config parsing
│   ├── doip_connection.py # DoIP transport / message handling
│   ├── log.py             # logging setup
│   ├── uds.py             # UDS services
│   └── uds_util.py        # UDS request builders
├── demo/
│   ├── config.json        # sample config (entity "tbox")
│   └── main.py            # runnable example
├── pyproject.toml
└── README.md
```

## Quick start

```bash
python3 demo/main.py
```

The demo reads `demo/config.json`. Edit the IP addresses and logical addresses
there to point at a real DoIP entity.

## Install

```bash
pip install -e .
```

## Usage

```python
from diag_client import DoipConnection, Uds, parse_doip_config
```
