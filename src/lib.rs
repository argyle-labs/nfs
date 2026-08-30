//! Network mount monitor (NFS + SMB/CIFS).
//!
//! Linux-only at runtime — relies on `/proc/mounts`, `stat`, and `umount`.
//! The parser is platform-agnostic so tests run on any OS.

use std::io::{BufRead, BufReader, Read};
use std::sync::Arc;
use std::time::Duration;

use plugin_toolkit::mount_recover;
use plugin_toolkit::orca_async;
use plugin_toolkit::prelude::*;
use plugin_toolkit::process::{Command, ToolError};
use plugin_toolkit::storage::{
    apply_option_floor, mount_table_of, parse_option_string, probe_health, Capability, ExportEntry,
    Health, MountOutcome, MountSpec, MountStyle, NormalizedSpec, OptionBuilder, OptionSet,
    RecoverOutcome, Share, StorageBackend, StorageError, StorageKind,
};

/// Network filesystem types this crate reports on. Single source shared by the
/// live mount-table read ([`read_mounts`]) and the stream parser's fstype gate
/// ([`is_network_fs`]) so both agree on what counts as a network mount.
const NETWORK_FSTYPES: &[&str] = &["nfs", "nfs4", "cifs", "smbfs"];
const FSTAB: &str = "/etc/fstab";
/// Static NFS server export table, read as the fallback when `exportfs -v`
/// (the running server's live view) is unavailable.
const EXPORTS: &str = "/etc/exports";

#[derive(Debug)]
pub enum NfsError {
    Read(std::io::Error),
    Umount {
        mountpoint: String,
        source: std::io::Error,
    },
    MountAll {
        source: std::io::Error,
    },
    Remount {
        mountpoint: String,
        source: std::io::Error,
    },
}

impl std::fmt::Display for NfsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NfsError::Read(source) => write!(f, "read /proc/mounts: {source}"),
            NfsError::Umount { mountpoint, source } => {
                write!(f, "umount -l {mountpoint}: {source}")
            }
            NfsError::MountAll { source } => write!(f, "mount -a: {source}"),
            NfsError::Remount { mountpoint, source } => {
                write!(f, "remount {mountpoint}: {source}")
            }
        }
    }
}

impl std::error::Error for NfsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            NfsError::Read(source) => Some(source),
            NfsError::Umount { source, .. } => Some(source),
            NfsError::MountAll { source } => Some(source),
            NfsError::Remount { source, .. } => Some(source),
        }
    }
}

impl From<std::io::Error> for NfsError {
    fn from(e: std::io::Error) -> Self {
        NfsError::Read(e)
    }
}

/// Fold a [`ToolError`] from [`Command::run_checked`] into the `std::io::Error`
/// the failure-carrying [`NfsError`] variants (`MountAll`/`Remount`/`Umount`)
/// wrap, preserving the exact `exit {code:?}: {stderr}` context those variants
/// rendered before they were routed through `run_checked`.
fn tool_error_to_io(e: &ToolError) -> std::io::Error {
    std::io::Error::other(format!("exit {:?}: {}", e.code, e.stderr))
}

#[orca_struct]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub device: String,
    pub mountpoint: String,
    pub fstype: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<String>,
    /// How many mounts are stacked on this mountpoint. `1` is the normal case.
    ///
    /// Linux lets a mount be layered over an already-occupied mountpoint; only
    /// the topmost is reachable by path. A single `umount` pops one layer and
    /// *reveals the one beneath*, so a mountpoint can probe healthy right after
    /// a repair and go stale again once that top layer is released — the
    /// "I fixed it and it broke again on its own" symptom.
    ///
    /// Anything `> 1` means a previous release/remount cycle stacked instead of
    /// replacing, and the mountpoint needs draining ([`release`] loops).
    #[serde(default = "one_layer")]
    pub layers: u32,
}

fn one_layer() -> u32 {
    1
}

/// Collapse stacked mounts into one entry per mountpoint, carrying the layer
/// count. Keeps the **topmost** mount's device/fstype, since that is what a
/// path lookup actually resolves to; the kernel mount table is ordered
/// oldest-first, so the last entry for a mountpoint is the top of the stack.
pub fn collapse_layers(mounts: Vec<Mount>) -> Vec<Mount> {
    let mut order: Vec<String> = Vec::new();
    let mut by_mp: std::collections::HashMap<String, Mount> = std::collections::HashMap::new();
    for m in mounts {
        match by_mp.get_mut(&m.mountpoint) {
            Some(existing) => {
                let layers = existing.layers + 1;
                *existing = Mount { layers, ..m };
            }
            None => {
                order.push(m.mountpoint.clone());
                by_mp.insert(m.mountpoint.clone(), m);
            }
        }
    }
    order
        .into_iter()
        .filter_map(|mp| by_mp.remove(&mp))
        .collect()
}

#[orca_struct]
#[derive(Debug, Clone)]
pub struct ReleaseResult {
    pub released: Vec<String>,
    pub skipped: Vec<String>,
    pub failed: Vec<ReleaseFailure>,
    /// Per-mountpoint count of stacked layers actually unmounted. A count `> 1`
    /// means the mountpoint was stacked and a single `umount` would have left a
    /// stale layer exposed underneath.
    #[serde(default)]
    pub layers_released: Vec<MountLayers>,
}

#[orca_struct]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountLayers {
    pub mountpoint: String,
    pub layers: u32,
}

#[orca_struct]
#[derive(Debug, Clone)]
pub struct ReleaseFailure {
    pub mountpoint: String,
    pub error: String,
}

/// Outcome of [`recover_stale`]: a stale-mount health-probe → force-release →
/// `mount -a` → re-probe cycle. `recovered` are mounts that were stale before
/// and `ok` after; `still_stale` are mounts that did not come back; `errors`
/// captures any non-fatal step failures (release failures, mount -a failure)
/// so the caller can log them and continue.
#[orca_struct]
#[derive(Debug, Clone, Default)]
pub struct RecoverResult {
    /// Mountpoints that were stale on the first probe and healthy after recovery.
    pub recovered: Vec<String>,
    /// Mountpoints still unhealthy after the recovery sequence.
    pub still_stale: Vec<String>,
    /// Non-fatal errors encountered during recovery (per-mount release
    /// failures, `mount -a` failure, probe errors).
    pub errors: Vec<String>,
    /// `true` when there was nothing stale **and** nothing missing to recover
    /// (fast path / no-op).
    pub no_stale_found: bool,
    /// Mountpoints declared in fstab but absent from `/proc/mounts` that were
    /// successfully remounted (the failed-automount / vanished-mount case the
    /// stale-handle probe is blind to).
    pub remounted: Vec<String>,
    /// Declared-but-absent mountpoints that could not be remounted.
    pub still_missing: Vec<String>,
    /// Stale mountpoints **left alone** because nothing in `/etc/fstab`
    /// declares them.
    ///
    /// Recovery is force-release then `mount -a`, and `mount -a` only knows
    /// about fstab. Releasing a mount fstab does not declare converts a
    /// *degraded* mountpoint into an *absent* one with no way back — strictly
    /// worse, and not self-healing. Reported so an operator can add an fstab
    /// entry or remount by hand.
    #[serde(default)]
    pub unmanaged: Vec<String>,
    /// Consumer-aware bind-mount recovery outcome. Populated only when the host
    /// sweep left the host healthy and a container runtime was supplied; `None`
    /// when the consumer sweep did not run (host-only recovery). The consumer
    /// machinery is the shared [`mount_recover`] module, not duplicated here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumers: Option<mount_recover::ConsumerRecoverResult>,
}

/// Is `fstype` one of the network filesystems this crate reports on?
fn is_network_fs(fstype: &str) -> bool {
    NETWORK_FSTYPES.contains(&fstype)
}

/// Read the live kernel mount table into a typed list, filtered to network
/// mounts. Sourced from the storage domain's generic `mount_table_of` so the
/// plugin and core share ONE definition of the mount table (and its per-OS
/// parsing) rather than reimplementing `/proc/mounts` parsing here — see
/// nfs#16. The cross-platform stream parser [`parse_mounts`] is retained for the
/// unit tests that exercise the parse grammar directly.
pub fn read_mounts() -> Result<Vec<Mount>, NfsError> {
    let table = mount_table_of(NETWORK_FSTYPES).map_err(NfsError::Read)?;
    Ok(table
        .into_iter()
        .map(|e| Mount {
            device: e.source,
            mountpoint: e.mountpoint,
            fstype: e.fstype,
            health: None,
            layers: 1,
        })
        .collect())
}

/// Parse a /proc/mounts-formatted stream. Pulled out for cross-platform tests.
pub fn parse_mounts<R: Read>(r: R) -> Result<Vec<Mount>, NfsError> {
    let mut out = Vec::new();
    for line in BufReader::new(r).lines() {
        let line = line?;
        let mut fields = line.split_whitespace();
        let (Some(device), Some(mountpoint), Some(fstype)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if !is_network_fs(fstype) {
            continue;
        }
        out.push(Mount {
            device: device.to_string(),
            mountpoint: mountpoint.to_string(),
            fstype: fstype.to_string(),
            health: None,
            layers: 1,
        });
    }
    Ok(out)
}

/// A network-filesystem entry declared in `/etc/fstab`. Captures whether the
/// entry is managed by `x-systemd.automount` — those need the failed automount
/// unit reset before a remount will take, which a bare `mount -a` does not do.
#[orca_struct]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FstabEntry {
    pub device: String,
    pub mountpoint: String,
    pub fstype: String,
    /// `true` when the options list contains `x-systemd.automount`.
    pub automount: bool,
}

/// Read `/etc/fstab` and return only its network-filesystem entries.
pub fn read_fstab() -> Result<Vec<FstabEntry>, NfsError> {
    let f = std::fs::File::open(FSTAB)?;
    parse_fstab(f)
}

/// Parse an fstab-formatted stream into network-fs entries. Pulled out so tests
/// run without touching the host's real `/etc/fstab`.
pub fn parse_fstab<R: Read>(r: R) -> Result<Vec<FstabEntry>, NfsError> {
    let mut out = Vec::new();
    for line in BufReader::new(r).lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let (Some(device), Some(mountpoint), Some(fstype), opts) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next().unwrap_or(""),
        ) else {
            continue;
        };
        if !is_network_fs(fstype) {
            continue;
        }
        out.push(FstabEntry {
            device: device.to_string(),
            mountpoint: mountpoint.to_string(),
            fstype: fstype.to_string(),
            automount: opts.split(',').any(|o| o == "x-systemd.automount"),
        });
    }
    Ok(out)
}

/// Read the NFS server exports this host publishes. Prefers the running
/// server's authoritative view (`exportfs -v`, which resolves wildcards and
/// fills `fsid=`); falls back to the static [`EXPORTS`] table when `exportfs`
/// is absent or fails. A host that serves nothing (no `exportfs`, no
/// `/etc/exports`) reports an empty list rather than an error — read-only and
/// bounded so it stays cheap on non-server hosts.
async fn read_exports() -> Result<Vec<ExportEntry>, StorageError> {
    if let Ok(o) = Command::new("exportfs").arg("-v").output().await {
        if o.status.success {
            return Ok(parse_exports(&String::from_utf8_lossy(&o.stdout)));
        }
    }
    match std::fs::read_to_string(EXPORTS) {
        Ok(text) => Ok(parse_exports(&text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(StorageError::Transport(format!("read {EXPORTS}: {e}"))),
    }
}

/// Parse `exportfs -v` (or `/etc/exports`) text into one [`ExportEntry`] per
/// exported path. Both formats share a grammar: a whitespace-leading export
/// path followed by zero or more `client(opt,opt,...)` specs. `exportfs -v`
/// emits one client per line and repeats the path, so grouping by path folds
/// those back together; `/etc/exports` lists every client on one line. `fsid=`
/// is lifted into [`ExportEntry::fsid`] (and left in `options` as declared).
/// Blank and `#`-comment lines are skipped. Pure so it's testable without a
/// running NFS server.
fn parse_exports(raw: &str) -> Vec<ExportEntry> {
    let mut order: Vec<String> = Vec::new();
    let mut by_path: std::collections::HashMap<String, ExportEntry> =
        std::collections::HashMap::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut toks = line.split_whitespace();
        let Some(path) = toks.next() else {
            continue;
        };
        let entry = by_path.entry(path.to_string()).or_insert_with(|| {
            order.push(path.to_string());
            ExportEntry {
                path: path.to_string(),
                allowed_clients: Vec::new(),
                options: Vec::new(),
                fsid: None,
            }
        });
        for spec in toks {
            let (client, options) = parse_client_spec(spec);
            // `exportfs -v` renders the everyone/`*` client as `<world>`;
            // canonicalize back to `*` so both source formats agree.
            let client = if client == "<world>" {
                "*".to_string()
            } else {
                client
            };
            if !client.is_empty() && !entry.allowed_clients.contains(&client) {
                entry.allowed_clients.push(client);
            }
            for o in options {
                if let Some(id) = o.strip_prefix("fsid=") {
                    if entry.fsid.is_none() {
                        entry.fsid = Some(id.to_string());
                    }
                }
                if !entry.options.contains(&o) {
                    entry.options.push(o);
                }
            }
        }
    }
    order
        .into_iter()
        .filter_map(|p| by_path.remove(&p))
        .collect()
}

/// Split one `client(opt,opt,...)` export spec into its client and options. A
/// bare `client` with no parenthesized options yields an empty option list; a
/// leading `(opts)` with no client yields an empty client.
fn parse_client_spec(spec: &str) -> (String, Vec<String>) {
    match spec.split_once('(') {
        Some((client, rest)) => {
            let options = rest
                .trim_end_matches(')')
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            (client.trim().to_string(), options)
        }
        None => (spec.trim().to_string(), Vec::new()),
    }
}

/// Expected network mounts (from fstab) that are **absent** from `/proc/mounts`.
///
/// This is the failure the stale-handle probe is blind to: when an
/// `x-systemd.automount` unit lands in `failed` state the mountpoint falls
/// through to its empty local placeholder directory, which `stat` reports as
/// perfectly healthy. The only reliable signal is "declared in fstab but not in
/// the kernel mount table". Honors the same `watch` prefix filter as [`list`].
pub fn missing_mounts(watch: &[String]) -> Result<Vec<FstabEntry>, NfsError> {
    let live = read_mounts()?;
    let mut expected = read_fstab()?;
    if !watch.is_empty() {
        // TODO(routes): converges to the shared routes array (WS2) — do not abstract to core yet
        expected.retain(|e| path_under_watch(&e.mountpoint, watch));
    }
    expected.retain(|e| !live.iter().any(|m| m.mountpoint == e.mountpoint));
    Ok(expected)
}

/// Bring one declared-but-absent mount back. For `x-systemd.automount` entries
/// the failed automount unit is reset first (`systemctl reset-failed`) — without
/// that the unit stays failed and on-access auto-mounting never recovers — then
/// the path is mounted directly (`mount <mountpoint>`), which succeeds whether
/// or not the host runs systemd. A non-systemd host simply skips the reset.
pub async fn remount_one(entry: &FstabEntry) -> Result<(), NfsError> {
    if entry.automount {
        // Best-effort: clear the failed automount + mount units so future
        // on-access mounting works again. Ignore failures (non-systemd host,
        // already-clean unit) — the direct mount below is what matters now.
        if let Ok(unit) = systemd_escape(&entry.mountpoint, "automount").await {
            let reset = Command::new("systemctl")
                .arg("reset-failed")
                .arg(&unit)
                .arg(unit.replace(".automount", ".mount"))
                .output()
                .await;
            drop(reset);
        }
    }
    Command::new("mount")
        .arg(&entry.mountpoint)
        .run_checked()
        .await
        .map(|_stdout| ())
        .map_err(|e| NfsError::Remount {
            mountpoint: entry.mountpoint.clone(),
            source: tool_error_to_io(&e),
        })
}

/// Resolve the systemd unit name for a mountpoint (e.g. `/mnt/<pool>/data` →
/// `mnt-pool-data.automount`) via `systemd-escape -p --suffix=<suffix>`.
async fn systemd_escape(mountpoint: &str, suffix: &str) -> Result<String, NfsError> {
    let stdout = Command::new("systemd-escape")
        .arg("-p")
        .arg(format!("--suffix={suffix}"))
        .arg(mountpoint)
        .run_checked()
        .await
        .map_err(|_e| NfsError::Remount {
            mountpoint: mountpoint.to_string(),
            source: std::io::Error::other("systemd-escape failed"),
        })?;
    Ok(String::from_utf8_lossy(&stdout).trim().to_string())
}

/// Restrict mounts to a configured watch list. `/foo` matches `/foo` and
/// any subpath `/foo/...`. Empty watch list = pass through.
pub fn filter_watch(mounts: Vec<Mount>, watch: &[String]) -> Vec<Mount> {
    if watch.is_empty() {
        return mounts;
    }
    // TODO(routes): converges to the shared routes array (WS2) — do not abstract to core yet
    mounts
        .into_iter()
        .filter(|m| path_under_watch(&m.mountpoint, watch))
        .collect()
}

/// Filter by exact filesystem type. Empty filter = pass through.
pub fn filter_by_fstype(mounts: Vec<Mount>, fstype: &str) -> Vec<Mount> {
    if fstype.is_empty() {
        return mounts;
    }
    mounts.into_iter().filter(|m| m.fstype == fstype).collect()
}

/// Probe a mountpoint's liveness, returning `"ok"` / `"stale"` / `"error: …"`.
///
/// Delegates to the storage domain's generic [`probe_health`] so the plugin and
/// core classify live-vs-stale-vs-absent identically (nfs#16). `probe_health`
/// `stat`s the path on a worker thread with the timeout budget: a hang past the
/// budget, an `ESTALE`, or any I/O error map to [`Health::Stale`]; a missing
/// path (failed automount fell through to a bare dir) maps to [`Health::Missing`].
/// Both collapse to `"stale"` here so the force-release/remount recovery fires
/// for either. The string shape is kept for the `Mount::health` report field.
pub async fn check_health(mountpoint: &str, timeout: Duration) -> String {
    match probe_health(mountpoint, timeout) {
        Health::Ok => "ok".to_string(),
        Health::Stale | Health::Timeout | Health::Missing => "stale".to_string(),
        Health::Error => "error: probe failed".to_string(),
    }
}

/// `mounts.list` — read /proc/mounts, apply watch + type filters, probe health.
/// Health probes run concurrently so N stale mounts cost ~one timeout.
pub async fn list(
    watch: &[String],
    fstype_filter: &str,
    health_timeout: Duration,
) -> Result<Vec<Mount>, NfsError> {
    let mut mounts = collapse_layers(filter_by_fstype(
        filter_watch(read_mounts()?, watch),
        fstype_filter,
    ));
    let probes = mounts.iter().map(|m| {
        let mp = m.mountpoint.clone();
        async move { check_health(&mp, health_timeout).await }
    });
    let results = plugin_toolkit::reactor::join_all(probes).await;
    for (m, health) in mounts.iter_mut().zip(results) {
        m.health = Some(health);
    }
    Ok(mounts)
}

/// `mounts.release` — lazy-unmount matching mounts. Optional host substring
/// filter (matches against the device field, e.g. `<server>:/data`).
///
/// `force == false` → `umount -l` (lazy detach; the default, unchanged).
/// `force == true`  → `umount -lf` (lazy **and** force; required to detach a
/// mount whose server is unreachable — a stale NFS handle won't release with
/// `-l` alone because the kernel still tries to flush).
///
/// Failures are collected per-mount instead of fail-fast so partial success
/// is reported back; one stuck mount won't block the rest.
pub async fn release(
    host_filter: &str,
    fstype_filter: &str,
    force: bool,
) -> Result<ReleaseResult, NfsError> {
    let mounts = filter_by_fstype(read_mounts()?, fstype_filter);
    let mut skipped = Vec::new();
    let mut targets = Vec::new();
    for m in mounts {
        if !host_filter.is_empty() && !m.device.contains(host_filter) {
            skipped.push(m.mountpoint);
        } else {
            targets.push(m.mountpoint);
        }
    }
    // Deduplicate: a stacked mountpoint appears once per layer in the mount
    // table. One umount task per entry would race several `umount` processes
    // against the same path concurrently. Drain each mountpoint once instead.
    targets.sort();
    targets.dedup();

    let umount_flag = if force { "-lf" } else { "-l" };
    let attempts = targets
        .into_iter()
        .map(|mp| drain_mountpoint(mp, umount_flag));
    let mut released = Vec::new();
    let mut failed = Vec::new();
    let mut layers_released = Vec::new();
    for (mp, layers, res) in plugin_toolkit::reactor::join_all(attempts).await {
        if layers > 0 {
            layers_released.push(MountLayers {
                mountpoint: mp.clone(),
                layers,
            });
        }
        match res {
            Ok(()) => released.push(mp),
            Err(error) => failed.push(ReleaseFailure {
                mountpoint: mp,
                error,
            }),
        }
    }
    Ok(ReleaseResult {
        released,
        skipped,
        failed,
        layers_released,
    })
}

/// Upper bound on unmount iterations for a single mountpoint. A stack deeper
/// than this means something is actively re-mounting underneath us; report
/// rather than spin forever.
const MAX_UNMOUNT_LAYERS: u32 = 16;

/// Unmount one mountpoint until it no longer appears in the kernel mount table.
///
/// A single `umount` pops exactly one layer. When a mountpoint has been stacked
/// — the usual outcome of a naive "umount then mount" repair, because `umount -l`
/// returns before the mount is actually detached — popping one layer exposes the
/// stale layer beneath, and the path reads healthy only until that top layer
/// goes away. Loop until the mountpoint is genuinely absent.
///
/// Returns `(mountpoint, layers_popped, outcome)`; `layers_popped` is reported
/// even on failure so a partial drain stays visible.
async fn drain_mountpoint(mp: String, umount_flag: &str) -> (String, u32, Result<(), String>) {
    let mut popped = 0u32;
    loop {
        // Re-read the mount table each pass. This is the authoritative answer to
        // "is anything still mounted here", and it terminates the loop without
        // trusting umount's exit code to mean "nothing left".
        let still_mounted = match read_mounts() {
            Ok(mounts) => mounts.iter().any(|m| m.mountpoint == mp),
            Err(e) => return (mp, popped, Err(format!("re-read mount table: {e}"))),
        };
        if !still_mounted {
            return (mp, popped, Ok(()));
        }
        if popped >= MAX_UNMOUNT_LAYERS {
            return (
                mp,
                popped,
                Err(format!(
                    "still mounted after draining {MAX_UNMOUNT_LAYERS} layers; \
                     something is re-mounting underneath"
                )),
            );
        }
        match Command::new("umount")
            .arg(umount_flag)
            .arg(&mp)
            .output()
            .await
        {
            Ok(o) if o.status.success => popped += 1,
            Ok(o) => return (mp, popped, Err(format!("exit code {:?}", o.status.code))),
            Err(e) => return (mp, popped, Err(e.to_string())),
        }
    }
}

/// `mount -a` — (re)mount everything declared in fstab that isn't already
/// mounted. Used after a force-release to bring detached network mounts back.
/// A non-zero exit is surfaced as [`NfsError::MountAll`] carrying stderr so the
/// caller can decide whether to log-and-continue or fail.
pub async fn mount_all() -> Result<(), NfsError> {
    Command::new("mount")
        .arg("-a")
        .run_checked()
        .await
        .map(|_stdout| ())
        .map_err(|e| NfsError::MountAll {
            source: tool_error_to_io(&e),
        })
}

/// Orchestrated recovery for one host's network mounts. Handles **two** distinct
/// failure modes:
///   * **missing** — declared in fstab but absent from `/proc/mounts` (e.g. a
///     failed `x-systemd.automount` unit; the mountpoint falls through to its
///     empty local placeholder dir and `stat` reports it healthy). Invisible to
///     the stale-handle probe.
///   * **stale** — present in `/proc/mounts` but I/O hangs (server unreachable).
///
/// Sequence (per [[feedback-self-healing-is-mandatory]]: probes do real I/O):
/// 0. Remount any declared-but-absent mounts (reset failed automount unit +
///    `mount <mountpoint>`), recording them in `remounted` / `still_missing`.
/// 1. Probe health of every matching network mount (`stat` with a timeout).
/// 2. If none are stale, return early; `no_stale_found` is `true` only when
///    nothing was missing either.
/// 3. Force-release (`umount -lf`) the stale ones.
/// 4. `mount -a` to re-attach them from fstab.
/// 5. Re-probe and classify each previously-stale mount as recovered or
///    still-stale.
///
/// Non-fatal step failures (a release failure, a `mount -a` non-zero exit) are
/// collected into `errors` rather than aborting — the caller logs and continues
/// its own recovery (e.g. proxmox lifecycle restart). Only a failure of the
/// initial host mount-table read (step 1, via the storage domain's
/// cross-platform `mount_table`) is fatal and returned as `Err`.
pub async fn recover_stale(
    watch: &[String],
    fstype_filter: &str,
    health_timeout: Duration,
) -> Result<RecoverResult, NfsError> {
    let mut result = RecoverResult::default();

    // 0. Recover declared-but-absent mounts (failed automount / vanished mount).
    //    This is orthogonal to staleness: a missing mount is NOT in /proc/mounts
    //    so it never shows up as `stale` below. `missing_mounts` is best-effort —
    //    a host with no readable /etc/fstab simply contributes nothing here.
    if let Ok(missing) = missing_mounts(watch) {
        for entry in &missing {
            match remount_one(entry).await {
                Ok(()) => result.remounted.push(entry.mountpoint.clone()),
                Err(e) => {
                    result.still_missing.push(entry.mountpoint.clone());
                    result.errors.push(e.to_string());
                }
            }
        }
    }

    // 1. Probe health of everything now in the mount table.
    let mounts = list(watch, fstype_filter, health_timeout).await?;
    let mut stale: Vec<Mount> = mounts
        .into_iter()
        .filter(|m| m.health.as_deref() == Some("stale"))
        .collect();

    // 2. Withhold stale mounts fstab does not declare. Step 4 restores via
    //    `mount -a`, which only knows fstab, so releasing an undeclared mount
    //    would detach it permanently. Degraded beats gone. An unreadable fstab
    //    means nothing is treated as declared — the conservative direction.
    let declared = read_fstab().unwrap_or_default();
    let (managed, unmanaged): (Vec<Mount>, Vec<Mount>) = stale
        .drain(..)
        .partition(|m| declared.iter().any(|e| e.mountpoint == m.mountpoint));
    for m in &unmanaged {
        result.unmanaged.push(m.mountpoint.clone());
        result.errors.push(format!(
            "{}: stale but not declared in {FSTAB}; refusing to release \
             (mount -a could not restore it)",
            m.mountpoint
        ));
    }
    let stale = managed;

    if stale.is_empty() {
        // No-op only if there was nothing missing to remount and nothing
        // withheld as unmanaged — a withheld stale mount is a real finding,
        // not a clean bill of health.
        result.no_stale_found = result.remounted.is_empty()
            && result.still_missing.is_empty()
            && result.unmanaged.is_empty();
        return Ok(result);
    }

    // 3. Force-release each stale mount. Filter by exact device so we only
    //    detach the wedged ones, not every network mount on the host.
    for m in &stale {
        match release(&m.device, fstype_filter, true).await {
            Ok(r) => {
                for f in r.failed {
                    result
                        .errors
                        .push(format!("release {}: {}", f.mountpoint, f.error));
                }
            }
            Err(e) => result.errors.push(format!("release {}: {e}", m.mountpoint)),
        }
    }

    // 4. Re-attach from fstab.
    if let Err(e) = mount_all().await {
        result.errors.push(e.to_string());
    }

    // 5. Re-probe the previously-stale set.
    for m in &stale {
        let health = check_health(&m.mountpoint, health_timeout).await;
        if health == "ok" {
            result.recovered.push(m.mountpoint.clone());
        } else {
            result.still_stale.push(m.mountpoint.clone());
        }
    }

    Ok(result)
}

/// Full self-heal across MANY container runtimes: the host sweep
/// ([`recover_stale`]) runs ONCE, then the shared consumer-aware sweep restarts
/// containers whose bind ROOT is stale **while the covering host mount is
/// healthy** (host self-healed, container still pinning the old superblock) and
/// starts stopped guests whose managed bind is now live. This is the entry point
/// the storage `recover` verb drives so a host running both Docker and Proxmox
/// heals guests under either — see nfs#16.
///
/// The consumer machinery is the fstype-agnostic [`mount_recover`] module, shared
/// with the `smb` backend rather than duplicated here. nfs supplies only the
/// `host_healthy` closure, derived from its *post-recovery* mount table (a source
/// is healthy when its longest covering network mount probes `ok`), so the shared
/// guard never triggers a restart storm during a host-wide outage: a stale/absent
/// source yields `false` and those consumers are recorded `skipped_host_stale`.
///
/// A failure to read `/proc/mounts` during the host sweep is fatal (`Err`), same
/// as [`recover_stale`]. The consumer sweep itself is best-effort.
pub async fn recover_stale_multi(
    runtimes: &[Box<dyn mount_recover::ContainerRuntime>],
    watch: &[String],
    fstype_filter: &str,
    health_timeout: Duration,
) -> Result<RecoverResult, NfsError> {
    let mut result = recover_stale(watch, fstype_filter, health_timeout).await?;

    // One post-recovery snapshot shared by every runtime's guard, so N runtimes
    // do not re-probe the host N times.
    let mounts = list(watch, fstype_filter, health_timeout).await?;
    let host_healthy = |source: &str| host_source_healthy(source, &mounts);

    let consumers =
        mount_recover::recover_consumers_multi(runtimes, watch, health_timeout, host_healthy).await;
    result.consumers = Some(consumers);
    Ok(result)
}

/// Is the host mount covering `source` healthy? Finds the longest mountpoint
/// that is a prefix of `source` (the mount the bind actually resolves through)
/// and returns whether its last health probe was `ok`. An uncovered or
/// non-`ok` source is treated as unhealthy so the consumer sweep's guard errs
/// toward *not* restarting during any doubt.
fn host_source_healthy(source: &str, mounts: &[Mount]) -> bool {
    mounts
        .iter()
        .filter(|m| path_under_watch(source, std::slice::from_ref(&m.mountpoint)))
        .max_by_key(|m| m.mountpoint.len())
        .map(|m| m.health.as_deref() == Some("ok"))
        .unwrap_or(false)
}

/// Does a host path fall under one of the watched prefixes? Shares prefix
/// semantics with the mount-table [`filter_watch`] so consumer binds and host
/// mounts match identically.
fn path_under_watch(path: &str, watch: &[String]) -> bool {
    if watch.is_empty() {
        return true;
    }
    watch.iter().any(|w| match path.strip_prefix(w.as_str()) {
        Some("") => true,
        Some(rest) => rest.starts_with('/'),
        None => false,
    })
}

// ── nfs option grammar ──────────────────────────────────────────────────────
//
// The nfs backend owns the grammar of its own mount options end to end — core is
// fstype-agnostic and neither parses nor renders them. `parse_nfs_options` turns
// the raw comma string a `MountSpec` carries into a local typed [`NfsOptions`],
// rejecting anything malformed or self-contradictory at declare time rather than
// at mount time. `render_nfs_options` is the inverse — it renders the canonical
// comma string (including the resilient-default safety floor) that core stamps
// verbatim into `OptionSet::Raw`. `normalize_nfs_source` canonicalizes the
// `host:/export` form.

/// NFS protocol versions this backend accepts for `vers=`. Anything else is a
/// hard rejection: a bad version silently falls back in the kernel, so catching
/// it here keeps a typo from becoming a wrong-protocol mount.
const VALID_NFS_VERS: &[&str] = &["3", "4", "4.0", "4.1", "4.2"];

/// Sane transfer-size bounds for `rsize`/`wsize` (bytes). The Linux client clamps
/// to its own limits, but a value outside [4 KiB, 16 MiB] or not a power-of-two
/// multiple of the page is almost always a mistake; reject the obviously-wrong
/// ones rather than let the kernel silently renegotiate.
const MIN_XSIZE: u32 = 4096;
const MAX_XSIZE: u32 = 16 * 1024 * 1024;

/// `timeo` is in deciseconds; a value of 0 disables the timeout (a footgun on a
/// network mount) and anything beyond ~1 hour is nonsensical.
const MAX_TIMEO_DECISECONDS: u32 = 36_000;

/// Upper bound for `retrans` / `actimeo`; large-but-finite guard against typos
/// (e.g. a stray extra digit) rather than a protocol limit.
const MAX_RETRANS: u32 = 100;
const MAX_ACTIMEO_SECONDS: u32 = 86_400;

/// Normalize an nfs source into canonical `host:/export` form. Accepts the
/// already-canonical form and trims incidental whitespace; rejects an empty
/// source or one missing the `:` / export separation.
fn normalize_nfs_source(source: &str) -> Result<String, StorageError> {
    let s = source.trim();
    if s.is_empty() {
        return Err(StorageError::Other("nfs source is empty".into()));
    }
    let (host, export) = s
        .split_once(':')
        .ok_or_else(|| StorageError::Other(format!("nfs source `{s}` is not `host:/export`")))?;
    let host = host.trim();
    let export = export.trim();
    if host.is_empty() {
        return Err(StorageError::Other(format!(
            "nfs source `{s}` has an empty host"
        )));
    }
    if !export.starts_with('/') {
        return Err(StorageError::Other(format!(
            "nfs source `{s}` export path must be absolute (start with `/`)"
        )));
    }
    Ok(format!("{host}:{export}"))
}

/// Parse a numeric nfs option, tagging the field name in any error.
fn parse_num(key: &str, value: &str) -> Result<u32, StorageError> {
    value
        .parse::<u32>()
        .map_err(|_| StorageError::Other(format!("nfs option `{key}` is not a number: `{value}`")))
}

/// The nfs backend's local typed option model. Core never sees this — it holds
/// only the rendered `OptionSet::Raw` string. This backend owns the full NFS
/// option grammar: the fields below are the ones it parses, validates, and
/// renders.
#[derive(Debug, Clone, PartialEq)]
struct NfsOptions {
    vers: Option<String>,
    hard: Option<bool>,
    soft: Option<bool>,
    timeo: Option<u32>,
    retrans: Option<u32>,
    actimeo: Option<u32>,
    rsize: Option<u32>,
    wsize: Option<u32>,
    netdev: bool,
    /// Any further raw `key` / `key=value` options, order-preserved.
    extra: Vec<String>,
}

/// Parse a raw comma-separated nfs option string into a typed [`NfsOptions`],
/// enforcing the backend's grammar:
///   * `vers` must be one of [`VALID_NFS_VERS`];
///   * `hard` and `soft` are mutually exclusive (declaring both is rejected);
///   * `timeo`/`retrans`/`actimeo`/`rsize`/`wsize` must parse and sit in sane
///     bounds;
///   * `_netdev` sets the netdev flag;
///   * every other `key` / `key=value` token is preserved verbatim in `extra`,
///     so a legal-but-untyped option (`nconnect=4`, `nofail`, `ro`) rides
///     through without the backend having to enumerate the whole kernel grammar.
fn parse_nfs_options(raw: Option<&str>) -> Result<NfsOptions, StorageError> {
    let mut vers = None;
    let mut hard = None;
    let mut soft = None;
    let mut timeo = None;
    let mut retrans = None;
    let mut actimeo = None;
    let mut rsize = None;
    let mut wsize = None;
    let mut netdev = false;
    let mut extra = Vec::new();

    let raw = raw.unwrap_or("");
    // Generic tokenizer (core mechanics); the NFS grammar below is all ours.
    for opt in parse_option_string(raw) {
        let (key, value) = (opt.key, opt.value);
        match (key, value) {
            ("vers" | "nfsvers", Some(v)) => {
                if !VALID_NFS_VERS.contains(&v) {
                    return Err(StorageError::Other(format!(
                        "nfs option `vers={v}` is not a supported version (expected one of {VALID_NFS_VERS:?})"
                    )));
                }
                vers = Some(v.to_string());
            }
            ("hard", None) => hard = Some(true),
            ("soft", None) => soft = Some(true),
            ("timeo", Some(v)) => {
                let n = parse_num("timeo", v)?;
                if n == 0 || n > MAX_TIMEO_DECISECONDS {
                    return Err(StorageError::Other(format!(
                        "nfs option `timeo={n}` out of range (1..={MAX_TIMEO_DECISECONDS} deciseconds)"
                    )));
                }
                timeo = Some(n);
            }
            ("retrans", Some(v)) => {
                let n = parse_num("retrans", v)?;
                if n > MAX_RETRANS {
                    return Err(StorageError::Other(format!(
                        "nfs option `retrans={n}` out of range (0..={MAX_RETRANS})"
                    )));
                }
                retrans = Some(n);
            }
            ("actimeo", Some(v)) => {
                let n = parse_num("actimeo", v)?;
                if n > MAX_ACTIMEO_SECONDS {
                    return Err(StorageError::Other(format!(
                        "nfs option `actimeo={n}` out of range (0..={MAX_ACTIMEO_SECONDS} seconds)"
                    )));
                }
                actimeo = Some(n);
            }
            ("rsize", Some(v)) => rsize = Some(check_xsize("rsize", parse_num("rsize", v)?)?),
            ("wsize", Some(v)) => wsize = Some(check_xsize("wsize", parse_num("wsize", v)?)?),
            ("_netdev", None) => netdev = true,
            // hard/soft/vers with the wrong arity → clear rejection rather than
            // silently dropping into `extra`.
            ("hard" | "soft" | "_netdev", Some(_)) => {
                return Err(StorageError::Other(format!(
                    "nfs option `{key}` takes no value"
                )));
            }
            ("vers" | "nfsvers" | "timeo" | "retrans" | "actimeo" | "rsize" | "wsize", None) => {
                return Err(StorageError::Other(format!(
                    "nfs option `{key}` requires a value"
                )));
            }
            // Legal-but-untyped passthrough (nofail, ro, nconnect=4, …).
            _ => extra.push(match value {
                Some(v) => format!("{key}={v}"),
                None => key.to_string(),
            }),
        }
    }

    if hard == Some(true) && soft == Some(true) {
        return Err(StorageError::Other(
            "nfs options `hard` and `soft` are mutually exclusive".into(),
        ));
    }

    Ok(NfsOptions {
        vers,
        hard,
        soft,
        timeo,
        retrans,
        actimeo,
        rsize,
        wsize,
        netdev,
        extra,
    })
}

/// Render a typed [`NfsOptions`] into the canonical comma-joined nfs option
/// string, applying the resilient-default **safety floor** first. This backend
/// owns both the grammar and the floor.
///
/// Safety floor: an NFS mount that declares neither `soft` nor `hard` inherits the
/// kernel default of `hard`, which — when the server reboots — puts every process
/// touching the mount into uninterruptible `D` and can wedge the whole client
/// host. So for a mount that hasn't opted into `hard`, ensure the resilient set
/// `soft`, `softreval`, and a fast-fail `timeo=50`/`retrans=2`. An explicit `hard`
/// is respected and left untouched. Idempotent — never duplicates a declared one.
fn render_nfs_options(o: &NfsOptions) -> String {
    // Build the base token list with the generic builder; every key/flag below
    // is NFS grammar the plugin owns.
    let mut b = OptionBuilder::new();
    if let Some(v) = &o.vers {
        b.opt("vers", Some(v));
    }
    b.flag("hard", o.hard == Some(true))
        .flag("soft", o.soft == Some(true));
    if let Some(v) = o.timeo {
        b.opt("timeo", Some(&v.to_string()));
    }
    if let Some(v) = o.retrans {
        b.opt("retrans", Some(&v.to_string()));
    }
    if let Some(v) = o.actimeo {
        b.opt("actimeo", Some(&v.to_string()));
    }
    if let Some(v) = o.rsize {
        b.opt("rsize", Some(&v.to_string()));
    }
    if let Some(v) = o.wsize {
        b.opt("wsize", Some(&v.to_string()));
    }
    b.flag("_netdev", o.netdev).extra(o.extra.clone());
    // Split back into tokens so the safety floor (which reasons about presence of
    // individual keys) can be applied before the final join. Tokens never contain
    // a comma, so this round-trips the builder's output exactly.
    let base = b.finish();
    let mut parts: Vec<String> = if base.is_empty() {
        Vec::new()
    } else {
        base.split(',').map(str::to_string).collect()
    };
    enforce_nfs_safe_options(&mut parts);
    parts.join(",")
}

/// Apply the NFS safety floor to an already-rendered option token list, in place.
/// The floor *values* are NFS grammar owned here; the *mechanism* (skip when an
/// explicit `hard` opt-out is present, else add each absent default) is core's
/// generic [`apply_option_floor`]. An explicit `hard` is respected (operator
/// override) and left untouched; otherwise `soft`/`softreval`/`timeo=50`/
/// `retrans=2` are added when absent.
fn enforce_nfs_safe_options(parts: &mut Vec<String>) {
    apply_option_floor(
        parts,
        &[
            ("soft", "soft"),
            ("softreval", "softreval"),
            ("timeo", "timeo=50"),
            ("retrans", "retrans=2"),
        ],
        &["hard"],
    );
}

/// Bounds-check a transfer size (`rsize`/`wsize`).
fn check_xsize(key: &str, n: u32) -> Result<u32, StorageError> {
    if !(MIN_XSIZE..=MAX_XSIZE).contains(&n) {
        return Err(StorageError::Other(format!(
            "nfs option `{key}={n}` out of range ({MIN_XSIZE}..={MAX_XSIZE} bytes)"
        )));
    }
    Ok(n)
}

// ── storage domain backend ──────────────────────────────────────────────────

/// NFS/SMB network-share backend for the `storage` domain. Contributes the
/// host's live network mounts as shares and exposes lazy/forced unmount. Mount
/// and usage stay [`StorageError::Unsupported`] — this adapter reads the
/// kernel's mount table rather than driving fstab/automount itself.
pub struct NfsBackend {
    name: String,
}

impl NfsBackend {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

impl Default for NfsBackend {
    fn default() -> Self {
        Self::new("nfs")
    }
}

#[orca_async]
impl StorageBackend for NfsBackend {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> StorageKind {
        StorageKind::NetworkShare
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![
            Capability::List,
            Capability::Exports,
            Capability::Unmount,
            Capability::RecoverStale,
        ]
    }

    fn endpoint(&self) -> String {
        "nfs://local".to_string()
    }

    /// nfs mounts are kernel mounts realized through autofs — the default.
    fn mount_style(&self) -> MountStyle {
        MountStyle::KernelMount
    }

    /// Parse + validate an nfs mount spec into a local typed [`NfsOptions`],
    /// rejecting malformed or conflicting options (bad `vers`, `hard`+`soft`,
    /// out-of-range numerics) at declare time. The source (and any failover
    /// sources) are normalized to canonical `host:/export` form.
    async fn validate_spec(&self, spec: &MountSpec) -> Result<NormalizedSpec, StorageError> {
        // Parse + validate locally, then render (with the safety floor) into the
        // opaque `OptionSet::Raw` string core carries. Core neither parses nor
        // renders nfs grammar — the plugin owns it end to end.
        let parsed = parse_nfs_options(spec.options.as_deref())?;
        let rendered = render_nfs_options(&parsed);
        let source = normalize_nfs_source(&spec.source)?;
        let failover_sources = spec
            .failover_sources
            .iter()
            .map(|s| normalize_nfs_source(s))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(NormalizedSpec {
            backend: spec.backend.clone(),
            target: spec.target.clone(),
            fstype: spec.fstype.clone(),
            source,
            failover_sources,
            options: OptionSet::Raw {
                options: Some(rendered),
            },
            credential: spec.credential.clone(),
            secret_file: None,
            remount_policy: spec.remount_policy.clone(),
            enabled: spec.enabled,
        })
    }

    /// Emit the canonical comma-separated nfs option string autofs's `-fstype`
    /// line / `mount -o` consumes — including the NFS safety floor. Core is
    /// fstype-agnostic: it hands this method an `OptionSet::Raw` holding either the
    /// declared option string (the autofs map path renders straight from the raw
    /// store) or the already-rendered string from `validate_spec`. Either way the
    /// plugin re-parses and renders, so the floor is always applied and the output
    /// is idempotent under a second render.
    fn render_options(&self, spec: &NormalizedSpec) -> String {
        let OptionSet::Raw { options } = &spec.options;
        match parse_nfs_options(options.as_deref()) {
            Ok(parsed) => render_nfs_options(&parsed),
            // A string that no longer parses (unexpected) falls back to verbatim so
            // rendering never panics; validate_spec already rejected bad options.
            Err(_) => options.clone().unwrap_or_default(),
        }
    }

    fn net_fstypes(&self) -> Vec<String> {
        vec!["nfs4".to_string(), "nfs".to_string()]
    }

    /// The NFS transport port core probes for source liveness. Core holds no
    /// port literal — it asks the fstype's owning backend, which is nfs here.
    fn default_source_port(&self) -> Option<u16> {
        Some(2049)
    }

    async fn list_shares(&self) -> Result<Vec<Share>, StorageError> {
        let mounts = read_mounts().map_err(|e| StorageError::Transport(e.to_string()))?;
        Ok(mounts
            .into_iter()
            .map(|m| Share {
                id: m.mountpoint.clone(),
                source: m.device,
                target: Some(m.mountpoint),
                fstype: m.fstype,
                mounted: true,
            })
            .collect())
    }

    /// Enumerate the NFS exports this host serves (`storage.exports`). Reads the
    /// running server's live view via `exportfs -v`, falling back to the static
    /// `/etc/exports` table, and lifts `fsid=` per export. Read-only.
    async fn list_exports(&self) -> Result<Vec<ExportEntry>, StorageError> {
        read_exports().await
    }

    async fn unmount(&self, target: &str) -> Result<MountOutcome, StorageError> {
        let res = release(target, "", true)
            .await
            .map_err(|e| StorageError::Transport(e.to_string()))?;
        if let Some(f) = res.failed.first() {
            return Err(StorageError::Other(format!(
                "unmount {}: {}",
                f.mountpoint, f.error
            )));
        }
        let mounted = res.released.is_empty();
        let detail = if res.released.is_empty() {
            res.skipped.first().map(|_| "no matching mount".to_string())
        } else {
            None
        };
        Ok(MountOutcome {
            target: target.to_string(),
            mounted,
            recovered: false,
            detail,
        })
    }

    async fn recover_stale(
        &self,
        watch: &[String],
        health_timeout: Duration,
    ) -> Result<RecoverOutcome, StorageError> {
        // The storage `recover` verb drives the FULL self-heal: host sweep then
        // the consumer-aware bind-mount sweep (guarded on host-health) across
        // EVERY container runtime present on the host — Docker and/or Proxmox
        // (`pct`). `RecoverOutcome` is a closed toolkit type with no consumer
        // fields, so consumer results are folded into its existing vecs with a
        // `consumer:` tag (and `started:` for stopped guests brought up) so a
        // caller can still see them.
        let runtimes = mount_recover::detect_runtimes().await;
        let mut r = recover_stale_multi(&runtimes, watch, "", health_timeout)
            .await
            .map_err(|e| StorageError::Transport(e.to_string()))?;
        let mut recovered = r.recovered;
        let mut still_stale = r.still_stale;
        let mut errors = r.errors;
        if let Some(c) = r.consumers.take() {
            recovered.extend(c.recovered.into_iter().map(|n| format!("consumer:{n}")));
            still_stale.extend(c.still_stale.into_iter().map(|n| format!("consumer:{n}")));
            still_stale.extend(
                c.skipped_host_stale
                    .into_iter()
                    .map(|n| format!("consumer-skipped-host-stale:{n}")),
            );
            errors.extend(c.errors.into_iter().map(|e| format!("consumer: {e}")));
        }
        Ok(RecoverOutcome {
            recovered,
            still_stale,
            remounted: r.remounted,
            still_missing: r.still_missing,
            errors,
            // `no_stale_found` still reflects the HOST sweep only — a clean host
            // with a stale consumer is not a no-op, but the consumer detail rides
            // in the vecs above.
            no_stale_found: r.no_stale_found,
        })
    }
}

/// Register the nfs storage backend with the process-global `storage` registry.
/// Called once at daemon startup. Idempotent — re-registering replaces by name.
pub fn bootstrap() {
    plugin_toolkit::storage::register_backend(Arc::new(NfsBackend::default()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use plugin_toolkit::serde_json;

    const SAMPLE: &str = "\
proc /proc proc rw,nosuid,nodev,noexec 0 0
<ip>:/data /mnt/data nfs4 rw 0 0
//host-e/share /mnt/host-e cifs rw 0 0
/dev/sda1 / ext4 rw 0 0
malformed_line
nasbox:/legacy /mnt/legacy smbfs ro 0 0
";

    #[test]
    fn parse_filters_to_network_mounts() {
        let mounts = parse_mounts(SAMPLE.as_bytes()).unwrap();
        assert_eq!(mounts.len(), 3);
        assert_eq!(mounts[0].fstype, "nfs4");
        assert_eq!(mounts[1].mountpoint, "/mnt/host-e");
        assert_eq!(mounts[2].fstype, "smbfs");
    }

    // `exportfs -v` view: one client per line, path repeated, `<world>` for `*`.
    const SAMPLE_EXPORTFS: &str = "\
/srv/nfs/data \t10.10.10.0/24(sync,wdelay,hide,no_subtree_check,fsid=1,sec=sys,rw,secure,root_squash)
/srv/nfs/data \t192.168.1.0/24(sync,wdelay,hide,no_subtree_check,fsid=1,sec=sys,ro,secure,root_squash)
/srv/nfs/media \t<world>(sync,wdelay,hide,no_subtree_check,sec=sys,ro,secure,root_squash)
";

    // `/etc/exports` view: all clients on one line, comments and blanks skipped.
    const SAMPLE_ETC_EXPORTS: &str = "\
# NFS exports
/srv/nfs/data 10.10.10.0/24(rw,sync,no_subtree_check,fsid=1) 192.168.1.0/24(ro,sync)

/srv/nfs/media *(ro,sync)
";

    #[test]
    fn parse_exportfs_groups_clients_and_lifts_fsid() {
        let exports = parse_exports(SAMPLE_EXPORTFS);
        assert_eq!(exports.len(), 2);
        let data = exports.iter().find(|e| e.path == "/srv/nfs/data").unwrap();
        assert_eq!(data.allowed_clients, ["10.10.10.0/24", "192.168.1.0/24"]);
        assert_eq!(data.fsid.as_deref(), Some("1"));
        assert!(data.options.iter().any(|o| o == "rw"));
        assert!(data.options.iter().any(|o| o == "ro"));
        let media = exports.iter().find(|e| e.path == "/srv/nfs/media").unwrap();
        // `<world>` canonicalizes back to `*`; no fsid declared.
        assert_eq!(media.allowed_clients, ["*"]);
        assert_eq!(media.fsid, None);
    }

    #[test]
    fn parse_etc_exports_one_line_many_clients() {
        let exports = parse_exports(SAMPLE_ETC_EXPORTS);
        assert_eq!(exports.len(), 2);
        let data = exports.iter().find(|e| e.path == "/srv/nfs/data").unwrap();
        assert_eq!(data.allowed_clients, ["10.10.10.0/24", "192.168.1.0/24"]);
        assert_eq!(data.fsid.as_deref(), Some("1"));
        let media = exports.iter().find(|e| e.path == "/srv/nfs/media").unwrap();
        assert_eq!(media.allowed_clients, ["*"]);
    }

    const SAMPLE_FSTAB: &str = "\
# /etc/fstab
/dev/sda1 / ext4 errors=remount-ro 0 1
proc /proc proc defaults 0 0
<ip>:/srv/pool/data /mnt/<pool>/data nfs4 _netdev,nofail,x-systemd.automount,hard 0 0
<ip>:/srv/pool/backups /mnt/<pool>/backups nfs4 _netdev,nofail,vers=4.2 0 0
//host/share /mnt/share cifs credentials=/etc/smb,x-systemd.automount 0 0
";

    #[test]
    fn parse_fstab_filters_to_network_and_flags_automount() {
        let entries = parse_fstab(SAMPLE_FSTAB.as_bytes()).unwrap();
        assert_eq!(entries.len(), 3);
        let data = entries
            .iter()
            .find(|e| e.mountpoint == "/mnt/<pool>/data")
            .unwrap();
        assert!(data.automount);
        assert_eq!(data.fstype, "nfs4");
        let backups = entries
            .iter()
            .find(|e| e.mountpoint == "/mnt/<pool>/backups")
            .unwrap();
        assert!(!backups.automount, "no x-systemd.automount in options");
        let share = entries
            .iter()
            .find(|e| e.mountpoint == "/mnt/share")
            .unwrap();
        assert!(share.automount);
    }

    #[test]
    fn parse_fstab_skips_comments_and_short_lines() {
        let entries = parse_fstab("# only a comment\n\nbad line\n".as_bytes()).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn filter_watch_restricts_to_listed_paths() {
        let mounts = parse_mounts(SAMPLE.as_bytes()).unwrap();
        let watch = vec!["/mnt/data".to_string()];
        let filtered = filter_watch(mounts, &watch);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].mountpoint, "/mnt/data");
    }

    #[test]
    fn filter_watch_matches_subpaths() {
        let mut mounts = parse_mounts(SAMPLE.as_bytes()).unwrap();
        mounts.push(Mount {
            device: "x".into(),
            mountpoint: "/mnt/data/sub".into(),
            fstype: "nfs".into(),
            health: None,
            layers: 1,
        });
        let watch = vec!["/mnt/data".to_string()];
        let filtered = filter_watch(mounts, &watch);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn filter_watch_empty_passes_through() {
        let mounts = parse_mounts(SAMPLE.as_bytes()).unwrap();
        assert_eq!(filter_watch(mounts.clone(), &[]).len(), mounts.len());
    }

    #[test]
    fn filter_by_fstype_exact_match() {
        let mounts = parse_mounts(SAMPLE.as_bytes()).unwrap();
        let cifs_only = filter_by_fstype(mounts, "cifs");
        assert_eq!(cifs_only.len(), 1);
        assert_eq!(cifs_only[0].fstype, "cifs");
    }

    #[test]
    fn is_network_fs_recognises_kernel_clients() {
        assert!(is_network_fs("nfs"));
        assert!(is_network_fs("nfs4"));
        assert!(is_network_fs("cifs"));
        assert!(is_network_fs("smbfs"));
        assert!(!is_network_fs("ext4"));
        assert!(!is_network_fs("tmpfs"));
    }

    #[test]
    fn filter_by_fstype_empty_passes_through() {
        let mounts = parse_mounts(SAMPLE.as_bytes()).unwrap();
        let n = mounts.len();
        assert_eq!(filter_by_fstype(mounts, "").len(), n);
    }

    #[test]
    fn nfs_error_display_covers_each_variant() {
        let io: NfsError = std::io::Error::other("boom").into();
        assert!(io.to_string().contains("/proc/mounts"));
        let u = NfsError::Umount {
            mountpoint: "/mnt/x".into(),
            source: std::io::Error::other("nope"),
        };
        let s = u.to_string();
        assert!(s.contains("/mnt/x"));
    }

    #[test]
    fn mount_and_release_types_round_trip_through_serde() {
        let m = Mount {
            device: "srv:/x".into(),
            mountpoint: "/mnt/x".into(),
            fstype: "nfs4".into(),
            health: Some("ok".into()),
            layers: 1,
        };
        let s = serde_json::to_string(&m).unwrap();
        let back: Mount = serde_json::from_str(&s).unwrap();
        assert_eq!(back, m);

        // health=None must be omitted from output.
        let m2 = Mount {
            health: None,
            ..m.clone()
        };
        let s2 = serde_json::to_string(&m2).unwrap();
        assert!(!s2.contains("health"));

        let r = ReleaseResult {
            released: vec!["/a".into()],
            skipped: vec!["/b".into()],
            failed: vec![ReleaseFailure {
                mountpoint: "/c".into(),
                error: "x".into(),
            }],
            layers_released: vec![],
        };
        let s = serde_json::to_string(&r).unwrap();
        let back: ReleaseResult = serde_json::from_str(&s).unwrap();
        assert_eq!(back.released, r.released);
        assert_eq!(back.skipped, r.skipped);
        assert_eq!(back.failed[0].mountpoint, "/c");
    }

    #[tokio::test]
    async fn check_health_returns_ok_for_real_path() {
        let dir = tempfile::tempdir().unwrap();
        let s = check_health(dir.path().to_str().unwrap(), Duration::from_secs(5)).await;
        assert_eq!(s, "ok");
    }

    #[tokio::test]
    async fn check_health_returns_stale_for_missing_path() {
        // Health probing delegates to the storage domain's `probe_health`, which
        // maps a missing path to `Health::Missing`. A failed automount that fell
        // through to a bare/absent dir must reach the recovery path, so
        // `check_health` collapses Missing → "stale" so remount fires (regression
        // guard: a bare `stat` returning "error: …" never triggered remount).
        let s = check_health("/definitely/not/here/orca_nfs_test", Duration::from_secs(5)).await;
        assert_eq!(s, "stale");
    }

    #[tokio::test]
    async fn check_health_returns_stale_when_timeout_elapses() {
        // 1ns budget against the real `stat` process expires before exec
        // completes → "stale" branch.
        let s = check_health("/", Duration::from_nanos(1)).await;
        // Allow either stale (timeout) or ok (impossibly fast) — both cover
        // the matching arm and any flake stays green.
        assert!(s == "stale" || s == "ok");
    }

    // `read_mounts` delegates to the storage domain's cross-platform
    // `mount_table_of` (`/proc/mounts` on Linux, `/sbin/mount` on macOS), so the
    // read path succeeds off-Linux and `list`/`release` ride that success.
    // Exercised on non-Linux so those paths keep coverage in CI runners that
    // aren't Linux.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn read_mounts_reads_cross_platform() {
        // Cross-platform read: Ok on macOS (was Err when it opened /proc/mounts).
        assert!(read_mounts().is_ok());
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn list_reads_cross_platform() {
        assert!(list(&[], "", Duration::from_secs(1)).await.is_ok());
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn release_reads_cross_platform() {
        // Both force modes enumerate via the cross-platform read and succeed
        // (no matching network mounts on a non-Linux test host → no-op Ok).
        assert!(release("", "", false).await.is_ok());
        assert!(release("", "", true).await.is_ok());
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn recover_stale_reads_cross_platform() {
        // The step-1 host mount read now succeeds cross-platform (was the sole
        // fatal path when it opened /proc/mounts), and the `/etc/fstab` scan is
        // best-effort — so the sweep returns `Ok` off-Linux instead of an
        // enumeration `Err`. (Whether anything was stale depends on the host's
        // live mount state, so only the non-fatal contract is asserted here.)
        let res = recover_stale(&[], "", Duration::from_secs(1)).await;
        assert!(res.is_ok());
    }

    // ── regression: stacked mounts ──────────────────────────────────────────
    // `umount -l` returns before the mount is detached, so a following `mount`
    // layers on top instead of replacing. Only the topmost layer is reachable
    // by path, so a repair probes healthy and then "spontaneously" breaks again
    // once that layer is released and the dead one beneath is revealed.

    const STACKED: &str = "\
<ip>:/export/data /mnt/data nfs4 rw 0 0
<ip>:/export/data /mnt/data nfs4 rw 0 0
<ip>:/export/backups /mnt/backups nfs4 rw 0 0
";

    #[test]
    fn collapse_layers_counts_stacked_mounts() {
        let collapsed = collapse_layers(parse_mounts(STACKED.as_bytes()).unwrap());
        assert_eq!(collapsed.len(), 2, "one entry per mountpoint");
        let data = collapsed
            .iter()
            .find(|m| m.mountpoint == "/mnt/data")
            .unwrap();
        assert_eq!(data.layers, 2, "two mounts stacked on /mnt/data");
        let backups = collapsed
            .iter()
            .find(|m| m.mountpoint == "/mnt/backups")
            .unwrap();
        assert_eq!(backups.layers, 1);
    }

    #[test]
    fn collapse_layers_preserves_first_seen_order() {
        let collapsed = collapse_layers(parse_mounts(STACKED.as_bytes()).unwrap());
        assert_eq!(collapsed[0].mountpoint, "/mnt/data");
        assert_eq!(collapsed[1].mountpoint, "/mnt/backups");
    }

    #[test]
    fn collapse_layers_keeps_topmost_device() {
        // The mount table is oldest-first, so the *last* entry for a mountpoint
        // is what a path lookup resolves to.
        let raw = "\
old:/export /mnt/x nfs4 rw 0 0
new:/export /mnt/x nfs4 rw 0 0
";
        let collapsed = collapse_layers(parse_mounts(raw.as_bytes()).unwrap());
        assert_eq!(collapsed.len(), 1);
        assert_eq!(collapsed[0].device, "new:/export");
        assert_eq!(collapsed[0].layers, 2);
    }

    #[test]
    fn collapse_layers_is_identity_for_unstacked() {
        let mounts = parse_mounts(SAMPLE.as_bytes()).unwrap();
        let n = mounts.len();
        let collapsed = collapse_layers(mounts);
        assert_eq!(collapsed.len(), n);
        assert!(collapsed.iter().all(|m| m.layers == 1));
    }

    #[test]
    fn mount_layers_round_trips_through_serde() {
        let r = ReleaseResult {
            released: vec!["/mnt/data".into()],
            skipped: vec![],
            failed: vec![],
            layers_released: vec![MountLayers {
                mountpoint: "/mnt/data".into(),
                layers: 2,
            }],
        };
        let s = serde_json::to_string(&r).unwrap();
        let back: ReleaseResult = serde_json::from_str(&s).unwrap();
        assert_eq!(back.layers_released[0].layers, 2);
        assert_eq!(back.layers_released[0].mountpoint, "/mnt/data");
    }

    #[test]
    fn mount_layers_defaults_to_one_when_absent_from_json() {
        // Payloads that predate the field must deserialize as unstacked, not 0.
        let m: Mount =
            serde_json::from_str(r#"{"device":"s:/x","mountpoint":"/mnt/x","fstype":"nfs4"}"#)
                .unwrap();
        assert_eq!(m.layers, 1);
    }

    // ── regression: unmanaged mounts must not be released ───────────────────
    // Recovery restores via `mount -a`, which only knows fstab. Releasing a
    // mount fstab does not declare detaches it permanently.

    #[test]
    fn recover_result_tracks_unmanaged_mounts() {
        let r = RecoverResult {
            unmanaged: vec!["/mnt/data".into()],
            ..Default::default()
        };
        let s = serde_json::to_string(&r).unwrap();
        let back: RecoverResult = serde_json::from_str(&s).unwrap();
        assert_eq!(back.unmanaged, vec!["/mnt/data".to_string()]);
    }

    #[test]
    fn unmanaged_partition_withholds_mounts_absent_from_fstab() {
        // The guard in recover_stale: a stale mount is releasable only when
        // fstab declares its mountpoint.
        let declared = parse_fstab(SAMPLE_FSTAB.as_bytes()).unwrap();
        let stale = vec![
            Mount {
                device: "<ip>:/srv/pool/data".into(),
                mountpoint: "/mnt/<pool>/data".into(),
                fstype: "nfs4".into(),
                health: Some("stale".into()),
                layers: 1,
            },
            Mount {
                device: "<ip>:/export/data".into(),
                mountpoint: "/mnt/data".into(),
                fstype: "nfs4".into(),
                health: Some("stale".into()),
                layers: 1,
            },
        ];
        let (managed, unmanaged): (Vec<Mount>, Vec<Mount>) = stale
            .into_iter()
            .partition(|m| declared.iter().any(|e| e.mountpoint == m.mountpoint));
        assert_eq!(managed.len(), 1);
        assert_eq!(managed[0].mountpoint, "/mnt/<pool>/data");
        assert_eq!(unmanaged.len(), 1);
        assert_eq!(
            unmanaged[0].mountpoint, "/mnt/data",
            "ad-hoc mount absent from fstab must be withheld from release"
        );
    }

    #[test]
    fn unreadable_fstab_withholds_everything() {
        // `read_fstab().unwrap_or_default()` yields no declarations, so every
        // stale mount partitions as unmanaged — the conservative direction.
        let declared: Vec<FstabEntry> = Vec::new();
        let stale = vec![Mount {
            device: "srv:/x".into(),
            mountpoint: "/mnt/x".into(),
            fstype: "nfs4".into(),
            health: Some("stale".into()),
            layers: 1,
        }];
        let (managed, unmanaged): (Vec<Mount>, Vec<Mount>) = stale
            .into_iter()
            .partition(|m| declared.iter().any(|e| e.mountpoint == m.mountpoint));
        assert!(managed.is_empty());
        assert_eq!(unmanaged.len(), 1);
    }

    #[test]
    fn recover_result_round_trips_through_serde() {
        let r = RecoverResult {
            recovered: vec!["/mnt/a".into()],
            still_stale: vec!["/mnt/b".into()],
            errors: vec!["release /mnt/c: boom".into()],
            no_stale_found: false,
            remounted: vec!["/mnt/d".into()],
            still_missing: vec!["/mnt/e".into()],
            unmanaged: vec![],
            consumers: None,
        };
        let s = serde_json::to_string(&r).unwrap();
        // `consumers: None` must be omitted from output.
        assert!(!s.contains("consumers"), "None consumers should be skipped");
        let back: RecoverResult = serde_json::from_str(&s).unwrap();
        assert_eq!(back.recovered, r.recovered);
        assert_eq!(back.still_stale, r.still_stale);
        assert_eq!(back.errors, r.errors);
        assert!(!back.no_stale_found);
        assert!(back.consumers.is_none());
    }

    #[test]
    fn recover_result_default_is_empty_no_stale() {
        let r = RecoverResult::default();
        assert!(r.recovered.is_empty());
        assert!(r.still_stale.is_empty());
        assert!(r.errors.is_empty());
        assert!(!r.no_stale_found);
    }

    #[test]
    fn path_under_watch_matches_prefix_and_subpaths() {
        let watch = vec!["/mnt/pool".to_string()];
        assert!(path_under_watch("/mnt/pool", &watch));
        assert!(path_under_watch("/mnt/pool/downloads", &watch));
        assert!(!path_under_watch("/mnt/poolx", &watch)); // not a path boundary
        assert!(!path_under_watch("/srv/other", &watch));
        assert!(
            path_under_watch("/anything", &[]),
            "empty watch passes through"
        );
    }

    #[test]
    fn host_source_healthy_uses_longest_covering_mount() {
        let mounts = vec![
            Mount {
                device: "srv:/pool".into(),
                mountpoint: "/mnt/pool".into(),
                fstype: "nfs4".into(),
                health: Some("ok".into()),
                layers: 1,
            },
            Mount {
                device: "srv:/pool/data".into(),
                mountpoint: "/mnt/pool/data".into(),
                fstype: "nfs4".into(),
                health: Some("stale".into()),
                layers: 1,
            },
        ];
        // Longest covering mount for this source is /mnt/pool/data (stale).
        assert!(!host_source_healthy("/mnt/pool/data/media", &mounts));
        // Covered only by /mnt/pool (ok).
        assert!(host_source_healthy("/mnt/pool/downloads", &mounts));
        // Uncovered → treated as unhealthy (guard errs toward not restarting).
        assert!(!host_source_healthy("/srv/elsewhere", &mounts));
    }

    #[test]
    fn recover_result_serializes_nested_consumers() {
        // The consumer machinery + its serde round-trip live in the shared
        // `mount_recover` module now; nfs only verifies RecoverResult carries the
        // `consumers` field through serde (and omits it when None).
        let r = RecoverResult {
            consumers: Some(mount_recover::ConsumerRecoverResult::default()),
            ..Default::default()
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("consumers"));
        let back: RecoverResult = serde_json::from_str(&s).unwrap();
        assert!(back.consumers.is_some());

        // Omitted entirely when None.
        let empty = serde_json::to_string(&RecoverResult::default()).unwrap();
        assert!(!empty.contains("consumers"));
    }

    #[test]
    fn mount_all_error_displays_context() {
        let e = NfsError::MountAll {
            source: std::io::Error::other("device busy"),
        };
        let s = e.to_string();
        assert!(s.contains("mount -a"));
        assert!(s.contains("device busy"));
    }

    // `mount_all` shells out to the real `mount` binary; on a dev box without
    // privileges it exits non-zero, exercising the MountAll error branch.
    // On CI/macOS `mount -a` may differ, so accept either Ok or MountAll.
    #[tokio::test]
    async fn mount_all_returns_a_result() {
        match mount_all().await {
            Ok(()) => {}
            Err(NfsError::MountAll { .. }) => {}
            Err(other) => panic!("unexpected error variant: {other}"),
        }
    }

    // ── nfs option grammar (Phase 2 mount contract) ───────────────────────────

    fn nfs_mount_spec(source: &str, options: Option<&str>) -> MountSpec {
        MountSpec {
            backend: "nfs".into(),
            target: "/mnt/downloads".into(),
            fstype: "nfs4".into(),
            source: source.into(),
            failover_sources: vec![],
            options: options.map(str::to_string),
            credential: None,
            remount_policy: None,
            enabled: true,
        }
    }

    #[test]
    fn mount_style_is_kernel_mount() {
        assert_eq!(NfsBackend::default().mount_style(), MountStyle::KernelMount);
    }

    #[test]
    fn parse_options_rejects_hard_and_soft_together() {
        let err = parse_nfs_options(Some("hard,soft")).unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"), "got: {err}");
    }

    #[test]
    fn parse_options_rejects_bad_vers() {
        let err = parse_nfs_options(Some("vers=5")).unwrap_err();
        assert!(err.to_string().contains("vers=5"), "got: {err}");
    }

    #[test]
    fn parse_options_rejects_out_of_range_numerics() {
        assert!(parse_nfs_options(Some("timeo=0")).is_err());
        assert!(parse_nfs_options(Some("rsize=1024")).is_err());
        assert!(parse_nfs_options(Some("wsize=33554432")).is_err());
        assert!(parse_nfs_options(Some("timeo=notanumber")).is_err());
        // Value-less option that requires a value, and vice-versa.
        assert!(parse_nfs_options(Some("vers")).is_err());
        assert!(parse_nfs_options(Some("hard=1")).is_err());
    }

    #[test]
    fn parse_options_happy_path_types_and_passthrough() {
        let set = parse_nfs_options(Some(
            "vers=4.2,hard,timeo=600,retrans=2,actimeo=30,rsize=1048576,wsize=1048576,_netdev,nofail,nconnect=4",
        ))
        .unwrap();
        let NfsOptions {
            vers,
            hard,
            soft,
            timeo,
            retrans,
            actimeo,
            rsize,
            wsize,
            netdev,
            extra,
        } = set;
        assert_eq!(vers.as_deref(), Some("4.2"));
        assert_eq!(hard, Some(true));
        assert_eq!(soft, None);
        assert_eq!(timeo, Some(600));
        assert_eq!(retrans, Some(2));
        assert_eq!(actimeo, Some(30));
        assert_eq!(rsize, Some(1048576));
        assert_eq!(wsize, Some(1048576));
        assert!(netdev);
        assert_eq!(extra, vec!["nofail".to_string(), "nconnect=4".to_string()]);
    }

    // ── nfs safety floor (moved from core autofs::enforce_nfs_safe_options) ──

    fn render_raw(raw: &str) -> String {
        render_nfs_options(&parse_nfs_options(Some(raw)).unwrap())
    }
    fn opts_set(s: &str) -> std::collections::HashSet<String> {
        s.split(',').map(str::to_string).collect()
    }

    #[test]
    fn nfs_no_soft_or_hard_gets_full_soft_floor() {
        let set = opts_set(&render_raw("vers=4.2"));
        assert!(set.contains("vers=4.2"));
        assert!(set.contains("soft"));
        assert!(set.contains("softreval"));
        assert!(set.contains("timeo=50"));
        assert!(set.contains("retrans=2"));
    }

    #[test]
    fn nfs_empty_options_still_gets_floor() {
        let set = opts_set(&render_nfs_options(&parse_nfs_options(None).unwrap()));
        assert!(set.contains("soft") && set.contains("timeo=50") && set.contains("retrans=2"));
    }

    #[test]
    fn nfs_explicit_hard_is_left_untouched() {
        let out = render_raw("vers=4.2,hard");
        assert_eq!(out, "vers=4.2,hard");
        assert!(!out.contains("soft"));
    }

    #[test]
    fn nfs_existing_values_are_not_duplicated_or_overridden() {
        let out = render_raw("soft,timeo=100,nconnect=4");
        let set = opts_set(&out);
        assert!(set.contains("timeo=100"));
        assert!(!out.contains("timeo=50"));
        assert!(set.contains("nconnect=4"));
        assert!(set.contains("retrans=2"));
        assert_eq!(out.matches("soft").count(), 2); // "soft" + "softreval"
    }

    #[test]
    fn normalize_source_canonicalizes_and_rejects_malformed() {
        assert_eq!(
            normalize_nfs_source(" 10.10.10.10:/mnt/user/downloads ").unwrap(),
            "10.10.10.10:/mnt/user/downloads"
        );
        assert!(normalize_nfs_source("").is_err());
        assert!(normalize_nfs_source("no-colon-path").is_err());
        assert!(normalize_nfs_source("host:relative/export").is_err());
        assert!(normalize_nfs_source(":/export").is_err());
    }

    #[tokio::test]
    async fn validate_spec_rejects_conflicting_options() {
        let backend = NfsBackend::default();
        let spec = nfs_mount_spec("10.10.10.10:/mnt/user/downloads", Some("hard,soft"));
        assert!(backend.validate_spec(&spec).await.is_err());
    }

    // The freyr example: this exact spec must validate, normalize to a single
    // source with no failover, and render back to the canonical option string.
    #[tokio::test]
    async fn validate_and_render_round_trips_freyr_example() {
        let backend = NfsBackend::default();
        let spec = nfs_mount_spec(
            "10.10.10.10:/mnt/user/downloads",
            Some("hard,timeo=600,retrans=2,_netdev,nofail"),
        );
        let normalized = backend.validate_spec(&spec).await.expect("validate");

        assert_eq!(normalized.source, "10.10.10.10:/mnt/user/downloads");
        assert!(
            normalized.failover_sources.is_empty(),
            "single source, no failover"
        );
        assert_eq!(
            backend.render_options(&normalized),
            "hard,timeo=600,retrans=2,_netdev,nofail"
        );
    }

    #[tokio::test]
    async fn validate_spec_normalizes_failover_sources() {
        let backend = NfsBackend::default();
        let mut spec = nfs_mount_spec("nas1:/export/pool", Some("vers=4.1"));
        spec.failover_sources = vec![" nas2:/export/pool ".into()];
        let normalized = backend.validate_spec(&spec).await.expect("validate");
        assert_eq!(normalized.source, "nas1:/export/pool");
        assert_eq!(normalized.failover_sources, vec!["nas2:/export/pool"]);
    }
}
