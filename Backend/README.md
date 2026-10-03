# Backend

One global uv environment lives in this folder (`pyproject.toml`, `uv.lock`, `.venv`).
`security/`, `fyp1/` and `fyp2/` all use it. Always run commands from `Backend/`.

```
uv sync                 # create .venv and install everything
uv run main.py          # start OmniGuard
uv run python -m fyp1.agent.supervisor
uv add <package>        # add a dependency for any part
```

Rust (optional, per-module speedups): `uv run maturin develop -m native/Cargo.toml`
