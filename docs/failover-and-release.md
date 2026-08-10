# NFS failover and release-on-reboot — proposed capabilities

Companion to `failure-modes.md`. Those modes are about a *single* mount breaking.
These are about **fleet behaviour** when an NFS server goes away — planned
(reboot/shutdown) or unplanned (wedge). Observed on a real fleet during the
2026-08-10 unraid incident; written as an implementation spec, not as shipped,
tested behaviour.

The fleet: a primary NAS (`willow`) and a Syncthing-replicated replica (`maple`)
both exporting the same `data`/`backups` shares. Clients mount via autofs direct
maps (`/-` → `/etc/auto.orca`).

---

## 1. Hang ≠ down

**Symptom.** A monitor pinging the server's TCP port, or running `showmount -e`,
reports the server **up** — while every client that touches the mount hangs.

**Cause.** NFSv4 I/O can be wedged (server-side `nfsd` in `D`-state, backing
store deadman-hung) while the TCP listener still accepts connections and the
mountd RPC still answers. Liveness at the socket layer says nothing about whether
reads complete.

**Why it matters for failover.** A failover trigger keyed on "host down"
(ping/port) will **never fire** during a wedge — the worst case — because the host
looks alive. The health signal must be an actual **timed read** of the mount, with
a hard deadline, classified as `wedged` when it neither succeeds nor fast-fails.

**Proposed plugin behaviour.** Health probe issues a bounded read (e.g. `stat`
plus a small `dd` with an overall timeout); `alive-but-wedged` is a distinct
state from `down` and from `healthy`, and it is a failover trigger.

## 2. Release-on-reboot (mounts must not hang when the server reboots)

**Symptom.** The NAS reboots for maintenance; every client with a `hard` mount of
it hangs — processes block in `D`, `df` freezes, the client may need its own
reboot to recover.

**Cause.** `hard` NFS mounts (the default) retry forever. With `timeo=…,retrans=…`
left long and autofs `--timeout=0` (never auto-unmount), a server that goes away
takes its clients with it.

**Policy that fixes it (validated in the incident).** Standardize managed mounts
to:

```
soft,softreval,timeo=50,retrans=2,nconnect=4,actimeo=30
```

plus autofs `--timeout=60` on the direct map (was `--timeout=0`). Under this
policy, when the server reboots the mount **errors** instead of hanging, the
client stays responsive, and autofs re-triggers the mount cleanly when the server
returns. Validated live: during a ~44s server outage, `soft`-mounted clients went
to "mount unavailable" (host stayed alive, no `D`-state) and auto-recovered on the
server's return; `hard`-mounted clients would have hung.

**Trade-off to document.** `soft` can surface I/O errors to applications under
transient loss. For datastores that must never see a short read (e.g. a live
database, a PBS chunkstore) prefer a health-checked failover to a replica over a
long `hard` timeout — never an unbounded `hard` mount on a box that reboots.

**Proposed plugin behaviour.** `storage.mount` renders the release-on-reboot
option set by default for managed autofs maps, and the plugin knows that a
**direct** autofs map change requires `systemctl restart autofs`, not `reload`
(`reload` does not re-read direct maps — the new mount never triggers).

## 3. Health-checked primary→replica failover

**Symptom.** Primary NAS wedges or is taken down; clients need to move to the
replica without hanging, and move back without flapping.

**Proposed behaviour.**

- **Trigger** on the mode-1 `wedged` signal or a real `down`, not on port
  liveness.
- **Drain then remount**: switch the map to the replica, `systemctl restart
  autofs`, confirm the replica is actually mounted **before** declaring success.
  For consumers pinned via a pre-start hook (e.g. a Proxmox LXC bind), the
  consumer must be stopped, the stale mount released (`umount -l`), the replica
  mounted, then the consumer restarted — a live bind does not re-point itself.
- **Return-to-primary** only after the primary passes the timed-read health check
  for a sustained window, to avoid flapping between two sick states.
- **Never fail over to an empty replica.** Verify the replica actually holds the
  data (non-empty, recent) before cutting traffic to it — a `sendreceive`
  replication set to an empty target can propagate *deletions* back to the
  primary. (This bit the PBS datastore in the incident; see the pbs plugin's
  `diagnostics.md`.)

## 4. Stale hard mounts hide from `findmnt`-less hosts

**Symptom.** A minimal client (no `findmnt`, no bash) still holds a `hard` mount
of the old server after a switch, and the switch script silently skipped it.

**Detection.** Do not depend on `findmnt`. Read `/proc/mounts` /
`/proc/self/mountinfo` directly and match on server IP + fstype `nfs4`. Release
leftovers with `umount -l`. Any switch that only handles the happy-path client
set leaves the wedged ones behind — enumerate from `/proc`, not from a tool that
may be absent.
