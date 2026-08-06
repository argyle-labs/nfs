# NFS failure modes

Field notes on how NFS mounts actually break, and what this plugin does about
each. Every mode below was observed on a real fleet; the behaviour described
under "What the plugin does" is covered by regression tests in `src/lib.rs`.

The modes are independent and routinely co-occur. Recovery that handles only one
of them leaves the others in place — and modes 2 and 3 are cases where a *naive*
repair makes things worse rather than better.

---

## 1. Stale handles that fail fast (not hang)

**Symptom.** Every client of a NAS reports `Stale file handle` on any access:

```
$ ls /mnt/data
ls: cannot access '/mnt/data': Stale file handle
```

**Cause.** The server rebooted or re-exported. Handles it previously issued
encode a generation number that is no longer valid, so the server *answers* — it
just answers `ESTALE` (errno 116). Clients that did not themselves reboot keep
presenting the dead handles indefinitely; NFS has no way to renegotiate them.

The client's kernel log shows the churn directly:

```
NFS: server <ip> error: fileid changed
NFS: state manager: check lease failed on NFSv4 server <ip> with error 13
```

**Why it is easy to miss.** There are two stale presentations and they look
nothing alike:

| | Server reachable? | `stat` behaviour |
|---|---|---|
| **Fast ESTALE** | yes | returns non-zero **immediately** |
| **Hang** | no | blocks in-kernel until the caller times out |

A probe that infers staleness *only* from a timeout classifies the fast case as
a generic error. If recovery then filters on `health == "stale"`, it skips
exactly the mounts that are broken — a silent no-op that reports success while
every mount stays wedged.

**What the plugin does.** `classify_stat_failure` maps an `ESTALE` stderr to
`"stale"`, and `check_health` collapses `Stale`, `Timeout`, and `Missing` to
`"stale"` so all three reach recovery.

---

## 2. Stacked mounts

**Symptom.** A mountpoint is repaired, verified healthy, then goes stale again
minutes later with no server-side event to explain it.

**Cause.** Linux permits mounting over an already-occupied mountpoint. The new
mount is layered on top and only the topmost is reachable by path — the one
underneath is hidden, not removed.

This is the normal outcome of a naive repair. `umount -l` detaches *lazily*: it
returns success immediately while the old mount lingers as long as anything
still references it. A `mount` issued right after therefore does not replace the
old mount, it stacks on it:

```
$ mount | grep -c ' /mnt/data '
2
```

The fresh top layer reads healthy, so the repair looks like it worked. When that
layer is later released the stale layer beneath is revealed and the mountpoint
appears to break again on its own.

**What the plugin does.**

- `Mount.layers` reports stack depth. `collapse_layers` folds a stacked
  mountpoint into a single entry so `list` reports each path once — previously
  a stacked path was listed once per layer, probed once per layer, with health
  that could disagree between entries. The topmost (path-resolving) device is
  kept.
- `release` **drains** rather than pops: it re-reads the mount table and unmounts
  until the mountpoint is genuinely absent, bounded by `MAX_UNMOUNT_LAYERS` so a
  path something else is actively re-mounting fails loudly instead of spinning.
  `ReleaseResult.layers_released` records how deep each stack actually was.
- Mountpoints are deduplicated before release. A stacked mountpoint appears once
  per layer in the mount table, and one `umount` task per entry would race
  several processes against the same path.

---

## 3. Ad-hoc mounts that recovery cannot restore

**Symptom.** Mounts work fine until a reboot, then vanish entirely. `mount -a`
does not bring them back.

**Cause.** The mount was established by hand or by a script and never recorded
in `/etc/fstab` (nor as a systemd `.mount` unit). It exists only in the kernel
mount table. Nothing recreates it at boot — and nothing can recreate it after a
release.

**Why this makes recovery dangerous.** The self-heal sequence is
release → `mount -a` → re-probe, and `mount -a` only knows about fstab.
Releasing a mount fstab does not declare converts a *degraded* mountpoint into an
*absent* one with no path back. That is strictly worse: a stale mount at least
still signals that something is wrong and still holds its configuration.

**What the plugin does.** `recover_stale` partitions stale mounts against fstab
and **withholds** the undeclared ones. They are reported in
`RecoverResult.unmanaged` with an explanatory line in `errors`, and
`no_stale_found` stays `false` so a withheld mount never reads as a clean bill
of health. If fstab is unreadable, nothing counts as declared and everything is
withheld — the conservative direction. Fixing one means adding an fstab entry:
a deliberate operator action, not something recovery should infer.

---

## 4. Missing mounts hidden behind a healthy-looking directory

**Symptom.** A mountpoint probes perfectly healthy but is empty, or shows stale
content.

**Cause.** When an `x-systemd.automount` unit enters `failed` state, the
mountpoint falls through to the empty local directory serving as its
placeholder. `stat` on a real local directory succeeds instantly — the probe has
nothing to detect. The mount is simply *absent*, and absence is invisible to any
check that only inspects mounts that exist.

**What the plugin does.** `missing_mounts` diffs fstab against the live mount
table; anything declared but not mounted is a finding regardless of how it
probes. `remount_one` clears the failed automount unit with `systemctl
reset-failed` before mounting — without that reset the unit stays failed and
on-access automounting never recovers — then mounts the path directly, which
works whether or not the host runs systemd.

---

## Operator checklist

After a NAS reboot, on every client that did **not** also reboot:

1. **Check stack depth first.** `mount | grep -c ' /mnt/<name> '` — anything
   above `1` means a previous repair stacked, and the mountpoint must be drained
   fully before remounting.
2. **Drain, don't pop.** Loop `umount -lf <mp>` until the mountpoint no longer
   appears in the mount table. A single unmount is not enough.
3. **Confirm fstab declares it** before releasing. If it does not, add the entry
   first — otherwise the release is unrecoverable.
4. **Verify with real I/O.** `stat` alone passes on an empty placeholder
   directory. List the contents and write a file.
5. **Re-probe after a few minutes.** Healthy immediately after repair and stale
   later is the stacking signature from mode 2.

`_netdev,nofail` on a client's fstab entry keeps a dead network mount from
blocking boot, which is what you want — but it also means a mount that never
comes back fails silently. Mode 4 is how that gets caught.
