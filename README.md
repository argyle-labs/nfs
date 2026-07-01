<p align="center">
  <img src="assets/icon-256.png" width="120" alt="nfs" />
</p>

# nfs

Registers an NFS `StorageBackend` — it mounts existing NFS exports into orca's storage domain.

A first-party [orca](https://github.com/argyle-labs/orca) plugin (storage-backend).

This is a **backend/adapter** — it has no service of its own; it wires an existing system into orca.

---

## Run it without orca

There's nothing to deploy: this plugin drives software you already run (upstream: <https://linux-nfs.org/>). Install/configure that directly, then register it with orca.


## With orca

orca drives this plugin through its generic surface — rich, nfs-specific data comes back in the typed `service.status` payload, never bespoke tools.

## Layout

- `src/` — the plugin (pure Rust): the `ServiceBackend` descriptor + `configure` / `status`.
- `assets/` — plugin icon.
