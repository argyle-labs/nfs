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

- `src/` — the plugin (pure Rust): the `StorageBackend` implementation — `mount` / `unmount` plus the stale-mount self-heal (`recover_stale`, which force-releases dead handles, replays `mount -a`, and re-probes).
- `docs/failure-modes.md` — how NFS mounts break in the field and what recovery does about each.
- `assets/` — plugin icon.

## Failure modes

NFS breaks in several distinct ways that look alike from a distance and need
different handling. [`docs/failure-modes.md`](docs/failure-modes.md) covers each
with its detection signal and the recovery this plugin performs:

1. **Stale handles that fail fast** — a rebooted server answers `ESTALE`
   immediately rather than hanging, so timeout-only detection misses it.
2. **Stacked mounts** — `umount -l` returns before detaching, so a following
   `mount` layers on top instead of replacing; the mountpoint probes healthy,
   then breaks again once the top layer is released.
3. **Ad-hoc mounts** — mounts absent from fstab cannot be restored by
   `mount -a`, which makes releasing them unrecoverable. `recover_stale`
   withholds them.
4. **Missing mounts** — a failed `x-systemd.automount` falls through to an empty
   local directory that probes perfectly healthy.
