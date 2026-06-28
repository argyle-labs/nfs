<p align="center">
  <img src="assets/icon-256.png" width="120" alt="nfs" />
</p>

# nfs — orca storage plugin

An [orca](https://github.com/argyle-labs/orca) **backend-only** plugin. It
carries zero `#[orca_tool]`s; instead it registers an NFS `StorageBackend` into
orca's generic `storage` domain across the cdylib FFI seam.

## What it does

orca treats every storage provider — NFS/SMB network shares, Proxmox-managed
disk storage, … — through one trait + one registry. This plugin contributes the
NFS facts and capabilities:

- **`list`** — read the live mount table and report NFS shares.
- **`unmount`** — lazy-unmount a target (`umount -lf`).
- **`recover_stale`** — the self-heal sequence: detect stale **and missing**
  NFS mounts (fstab vs `/proc/mounts`), `umount -lf` the stale ones, `mount -a`
  to restore, then health-probe each mount point with a real `stat`.

When orca's `plugin-loader` `dlopen`s the built cdylib, a successful load
registers an `nfs` backend into the process-global storage registry. Every call
against that backend is a host-side `StorageProxy` that marshals its args to
JSON and calls back into this library's `invoke()` under the
`storage.__backend.nfs.*` namespace.

## Building

```sh
# cdylib artifact the loader dlopens
cargo build --lib

# in-crate test harness (22 tests)
cargo test
```

A checked-out `argyle-labs/orca` at `../orca` resolves the `plugin-toolkit`
dependency locally via the `[patch]` in `.cargo/config.toml`. Otherwise it
resolves from orca's `dev` branch.

## Single dependency

Per orca's plugin contract, this plugin reaches the entire orca system —
infra and the `storage` domain (`plugin_toolkit::storage`) — through
`plugin-toolkit` alone. The only other dependency is `abi_stable`, required
because `#[export_root_module]` emits bare `::abi_stable` paths at the cdylib
FFI boundary.
