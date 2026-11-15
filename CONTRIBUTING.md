# Contributing to agent-witness

Contributions are welcome!

## Development
```bash
git clone https://github.com/devsoniclk/agent-witness.git
cd agent-witness
pip install -e ".[dev]"
pytest tests/ -v
```

## RFC 6962 Compliance
All leaf and node hashing modifications must preserve the domain separation prefixes:
- `0x00` for leaf nodes
- `0x01` for internal branches
