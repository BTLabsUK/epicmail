# epicmail

An Epicbox-compatible relay in one static binary, with SQLite inside. It speaks the Epicbox
websocket protocol (2.0.0/3.0.0) and the `mux/1` extension, so existing Epic wallets work
unchanged.

- Operating guide: `docs/operating.md`
- Configuration: `packaging/epicmail.example.toml`
- `mux/1` extension: `docs/mux-1.md`
- Load test: `docs/loadtest.md`
- Build a static binary: `tools/build-static.sh`
- Systemd unit, nginx and Caddy examples: `packaging/`
