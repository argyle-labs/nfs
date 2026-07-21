//! Network mount monitor (NFS + SMB/CIFS).
//!
//! Linux-only at runtime — relies on `/proc/mounts`, `stat`, and `umount`.
//! The parser is platform-agnostic so tests run on any OS.

use std::io::{BufRead, BufReader, Read};
use std::sync::Arc;
use std::time::Duration;

use plugin_toolkit::orca_async;
use plugin_toolkit::prelude::*;
use plugin_toolkit::process::Command;
use plugin_toolkit::storage::{
    render_option_set, Capability, MountOutcome, MountSpec, MountStyle, NormalizedSpec, OptionSet,
    RecoverOutcome, Share, StorageBackend, StorageError, StorageKind,
};

const PROC_MOUNTS: &str = "/proc/mounts";
const FSTAB: &str = "/etc/fstab";

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

#[plugin_struct]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub device: String,
    pub mountpoint: String,
    pub fstype: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<String>,
}

#[plugin_struct]
#[derive(Debug, Clone)]
pub struct ReleaseResult {
    pub released: Vec<String>,
    pub skipped: Vec<String>,
    pub failed: Vec<ReleaseFailure>,
}

#[plugin_struct]
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
#[plugin_struct]
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
    /// Consumer-aware bind-mount recovery outcome (Part B). Populated only when
    /// the host sweep left the host healthy and a container runtime was supplied;
    /// `None` when the consumer sweep did not run (host-only recovery). See
    /// [`recover_stale_consumers`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumers: Option<ConsumerRecoverResult>,
}

/// Network filesystem types this crate reports on.
fn is_network_fs(fstype: &str) -> bool {
    matches!(fstype, "nfs" | "nfs4" | "cifs" | "smbfs")
}

/// Read `/proc/mounts` into a typed list. Returns only network mounts.
pub fn read_mounts() -> Result<Vec<Mount>, NfsError> {
    let f = std::fs::File::open(PROC_MOUNTS)?;
    parse_mounts(f)
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
        });
    }
    Ok(out)
}

/// A network-filesystem entry declared in `/etc/fstab`. Captures whether the
/// entry is managed by `x-systemd.automount` — those need the failed automount
/// unit reset before a remount will take, which a bare `mount -a` does not do.
#[plugin_struct]
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
        expected.retain(|e| {
            watch
                .iter()
                .any(|w| match e.mountpoint.strip_prefix(w.as_str()) {
                    Some("") => true,
                    Some(rest) => rest.starts_with('/'),
                    None => false,
                })
        });
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
    let out = Command::new("mount")
        .arg(&entry.mountpoint)
        .output()
        .await
        .map_err(|source| NfsError::Remount {
            mountpoint: entry.mountpoint.clone(),
            source,
        })?;
    if out.status.success {
        Ok(())
    } else {
        Err(NfsError::Remount {
            mountpoint: entry.mountpoint.clone(),
            source: std::io::Error::other(format!(
                "exit {:?}: {}",
                out.status.code,
                String::from_utf8_lossy(&out.stderr).trim()
            )),
        })
    }
}

/// Resolve the systemd unit name for a mountpoint (e.g. `/mnt/<pool>/data` →
/// `mnt-pool-data.automount`) via `systemd-escape -p --suffix=<suffix>`.
async fn systemd_escape(mountpoint: &str, suffix: &str) -> Result<String, NfsError> {
    let out = Command::new("systemd-escape")
        .arg("-p")
        .arg(format!("--suffix={suffix}"))
        .arg(mountpoint)
        .output()
        .await
        .map_err(|source| NfsError::Remount {
            mountpoint: mountpoint.to_string(),
            source,
        })?;
    if out.status.success {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(NfsError::Remount {
            mountpoint: mountpoint.to_string(),
            source: std::io::Error::other("systemd-escape failed"),
        })
    }
}

/// Restrict mounts to a configured watch list. `/foo` matches `/foo` and
/// any subpath `/foo/...`. Empty watch list = pass through.
pub fn filter_watch(mounts: Vec<Mount>, watch: &[String]) -> Vec<Mount> {
    if watch.is_empty() {
        return mounts;
    }
    mounts
        .into_iter()
        .filter(|m| {
            watch
                .iter()
                .any(|w| match m.mountpoint.strip_prefix(w.as_str()) {
                    Some("") => true,
                    Some(rest) => rest.starts_with('/'),
                    None => false,
                })
        })
        .collect()
}

/// Filter by exact filesystem type. Empty filter = pass through.
pub fn filter_by_fstype(mounts: Vec<Mount>, fstype: &str) -> Vec<Mount> {
    if fstype.is_empty() {
        return mounts;
    }
    mounts.into_iter().filter(|m| m.fstype == fstype).collect()
}

/// Classify a failed `stat` by its stderr. A stale NFS handle can fail two
/// ways: the kernel *blocks* (detected by the caller's timeout → `"stale"`), or
/// it fails *fast* with `ESTALE` — stderr `... Stale file handle`. The fast
/// path is exactly the consumer-bind failure mode the original probe missed: it
/// returned `"error: …"`, so the force-release/remount recovery never fired.
/// Any other failure (ENOENT, EACCES, …) stays a plain `"error: …"`.
///
/// Returns the health string the probe should report (`"stale"` for ESTALE,
/// otherwise `"error: <stderr>"`). Pure + case-insensitive so it's unit-testable
/// without spawning `stat`.
pub fn classify_stat_failure(stderr: &str) -> String {
    let trimmed = stderr.trim();
    if trimmed.to_ascii_lowercase().contains("stale file handle") {
        "stale".to_string()
    } else {
        format!("error: {trimmed}")
    }
}

/// `stat <mountpoint>` with a timeout. Returns `"ok"` / `"stale"` / `"error: …"`.
/// `stat` blocks in-kernel on a stale NFS handle when the server is unreachable
/// (timeout → `"stale"`), but fails *fast* with `ESTALE` when the superblock was
/// replaced under a still-pinned mount (stderr classified → `"stale"`). Both
/// must reach the stale branch so recovery fires.
pub async fn check_health(mountpoint: &str, timeout: Duration) -> String {
    let fut = Command::new("stat").arg("--").arg(mountpoint).output();
    match plugin_toolkit::time::timeout(timeout, fut).await {
        None => "stale".to_string(),
        Some(Err(e)) => format!("error: {e}"),
        Some(Ok(out)) if out.status.success => "ok".to_string(),
        Some(Ok(out)) => classify_stat_failure(&String::from_utf8_lossy(&out.stderr)),
    }
}

/// `mounts.list` — read /proc/mounts, apply watch + type filters, probe health.
/// Health probes run concurrently so N stale mounts cost ~one timeout.
pub async fn list(
    watch: &[String],
    fstype_filter: &str,
    health_timeout: Duration,
) -> Result<Vec<Mount>, NfsError> {
    let mut mounts = filter_by_fstype(filter_watch(read_mounts()?, watch), fstype_filter);
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
    let umount_flag = if force { "-lf" } else { "-l" };
    let attempts = targets.into_iter().map(|mp| async move {
        let res = Command::new("umount")
            .arg(umount_flag)
            .arg(&mp)
            .output()
            .await
            .map(|o| o.status);
        (mp, res)
    });
    let mut released = Vec::new();
    let mut failed = Vec::new();
    for (mp, res) in plugin_toolkit::reactor::join_all(attempts).await {
        match res {
            Ok(status) if status.success => released.push(mp),
            Ok(status) => failed.push(ReleaseFailure {
                mountpoint: mp,
                error: format!("exit code {:?}", status.code),
            }),
            Err(e) => failed.push(ReleaseFailure {
                mountpoint: mp,
                error: e.to_string(),
            }),
        }
    }
    Ok(ReleaseResult {
        released,
        skipped,
        failed,
    })
}

/// `mount -a` — (re)mount everything declared in fstab that isn't already
/// mounted. Used after a force-release to bring detached network mounts back.
/// A non-zero exit is surfaced as [`NfsError::MountAll`] carrying stderr so the
/// caller can decide whether to log-and-continue or fail.
pub async fn mount_all() -> Result<(), NfsError> {
    let out = Command::new("mount")
        .arg("-a")
        .output()
        .await
        .map_err(|source| NfsError::MountAll { source })?;
    if out.status.success {
        Ok(())
    } else {
        Err(NfsError::MountAll {
            source: std::io::Error::other(format!(
                "exit {:?}: {}",
                out.status.code,
                String::from_utf8_lossy(&out.stderr).trim()
            )),
        })
    }
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
/// its own recovery (e.g. proxmox lifecycle restart). Only a failure to read
/// `/proc/mounts` (the initial enumeration) is fatal and returned as `Err`.
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
    let stale: Vec<Mount> = mounts
        .into_iter()
        .filter(|m| m.health.as_deref() == Some("stale"))
        .collect();

    if stale.is_empty() {
        // No-op only if there was also nothing missing to remount.
        result.no_stale_found = result.remounted.is_empty() && result.still_missing.is_empty();
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

/// Full self-heal: the host sweep ([`recover_stale`]) **followed by** the
/// consumer-aware bind-mount sweep ([`recover_stale_consumers`]).
///
/// This is the entry the periodic self-heal path uses. The consumer sweep runs
/// *after* the host sweep so any host-level staleness is remediated first, then:
///   * a per-bind-source host-health closure is derived from the *post-recovery*
///     mount table (a source is healthy when its covering mount probes `ok`);
///   * the consumer sweep restarts only those containers whose bind ROOT is
///     ESTALE **while the covering host mount is healthy** — the exact incident
///     signature (host self-healed, container still pinning the old superblock).
///
/// The guard means a host-wide outage (host mounts still stale) never triggers a
/// container restart storm: `host_healthy(source)` returns `false` for a source
/// whose mount is stale or absent, so those consumers are recorded as
/// `skipped_host_stale` instead of restarted.
///
/// A failure to read `/proc/mounts` during the host sweep is fatal (`Err`), same
/// as [`recover_stale`]. The consumer sweep itself is best-effort and folds its
/// own failures into `ConsumerRecoverResult::errors`.
pub async fn recover_stale_with_consumers(
    runtime: &dyn ContainerRuntime,
    watch: &[String],
    fstype_filter: &str,
    health_timeout: Duration,
) -> Result<RecoverResult, NfsError> {
    let mut result = recover_stale(watch, fstype_filter, health_timeout).await?;

    // Snapshot the post-recovery mount table once so the guard closure does not
    // re-probe per consumer. A bind source is host-healthy when the longest
    // covering network mount is present and stats `ok`.
    let mounts = list(watch, fstype_filter, health_timeout).await?;
    let host_healthy = |source: &str| host_source_healthy(source, &mounts);

    let consumers = recover_stale_consumers(runtime, watch, health_timeout, host_healthy).await;
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

// ── consumer-aware bind-mount staleness (Part B) ─────────────────────────────
//
// The host mount can self-heal (autofs re-triggers, a fresh superblock lands)
// and the host-side `stat` probe reports healthy — yet a long-running container
// that bind-mounted a subpath of the pool still pins the OLD superblock. Reading
// the bind's ROOT inside that container returns ESTALE ("Stale file handle")
// even though the host is fine; already-cached subdirs still stat OK, so the
// staleness hides until a consumer walks the root. Restarting the container
// re-binds the fresh mount and clears it.
//
// The host-side probe is structurally blind to this (the host WAS healthy), so
// recovery needs a consumer-aware pass: enumerate containers bind-mounting a
// watched host path, probe the bind ROOT *inside* each container, and — only
// when the host mount is healthy but the consumer is ESTALE — restart that
// consumer. Guarded so a host-wide outage never triggers a restart storm.

/// One host→container bind of a watched path, as seen by the container runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumerBind {
    /// Container id (runtime-native handle used for exec/restart).
    pub container_id: String,
    /// Human-friendly container name for reporting.
    pub container_name: String,
    /// The host path being bind-mounted (matches a watched prefix).
    pub host_source: String,
    /// The path the bind is mounted at *inside* the container — the ROOT we
    /// probe for ESTALE.
    pub container_target: String,
}

/// Result of a `stat` probe of a bind ROOT inside a container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsumerProbe {
    Ok,
    Stale,
}

/// Abstraction over the container runtime so the consumer sweep is testable
/// without Docker. The production impl ([`DockerCli`]) shells `docker` behind
/// this trait. The toolkit does expose a `containers` seam, but it pulls the
/// bollard/Docker client the thin nfs plugin deliberately avoids, so the runtime
/// is reached via `plugin_toolkit::process::Command` confined to this one
/// swappable seam rather than scattered `Command::new("docker")` calls.
#[orca_async]
pub trait ContainerRuntime: Send + Sync {
    /// Enumerate containers bind-mounting any host path under one of `watch`.
    /// Same prefix semantics as [`filter_watch`] (`/foo` matches `/foo` and
    /// `/foo/...`).
    async fn binds_under(&self, watch: &[String]) -> Result<Vec<ConsumerBind>, NfsError>;

    /// Probe `path` inside container `id` with a timeout. ESTALE (or a hang past
    /// the budget) → [`ConsumerProbe::Stale`]; success → `Ok`. Any other failure
    /// is surfaced as `Err` for the caller to record.
    async fn probe_path(
        &self,
        id: &str,
        path: &str,
        timeout: Duration,
    ) -> Result<ConsumerProbe, NfsError>;

    /// Restart container `id` to re-bind the fresh mount.
    async fn restart(&self, id: &str) -> Result<(), NfsError>;
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

/// Structured outcome of [`recover_stale_consumers`], mirroring [`RecoverResult`]:
/// consumers are categorized so the caller can log and continue.
#[plugin_struct]
#[derive(Debug, Clone, Default)]
pub struct ConsumerRecoverResult {
    /// Containers whose bind ROOT probed healthy — nothing to do.
    pub healthy: Vec<String>,
    /// Containers that were ESTALE and were restarted back to health (host
    /// mount healthy).
    pub recovered: Vec<String>,
    /// Containers that probed ESTALE but were NOT restarted because the host
    /// mount for that path was itself stale (host-wide outage guard) — a restart
    /// would not help and could storm.
    pub skipped_host_stale: Vec<String>,
    /// Containers restarted but still ESTALE afterwards, or whose restart failed.
    pub still_stale: Vec<String>,
    /// Non-fatal per-consumer errors (enumerate/probe/restart failures).
    pub errors: Vec<String>,
    /// `true` when no watched bind was found at all (fast path / no-op).
    pub no_consumers_found: bool,
}

/// Consumer-aware bind-mount staleness detection + remediation.
///
/// 1. Enumerate containers bind-mounting any host path under `watch`.
/// 2. Probe the bind ROOT inside each container for ESTALE.
/// 3. If the *host* mount for that path is healthy but the consumer is ESTALE →
///    stale bind → restart the consumer (re-binds the fresh superblock).
/// 4. Re-probe restarted consumers and classify.
///
/// `host_healthy(host_source) -> bool` reports whether the host-side mount
/// covering that bind source is currently healthy; the sweep only restarts when
/// the host is healthy (never during a host-wide outage). Idempotent — a
/// consumer already healthy is left alone.
pub async fn recover_stale_consumers<F>(
    runtime: &dyn ContainerRuntime,
    watch: &[String],
    health_timeout: Duration,
    host_healthy: F,
) -> ConsumerRecoverResult
where
    F: Fn(&str) -> bool,
{
    let mut result = ConsumerRecoverResult::default();

    let binds = match runtime.binds_under(watch).await {
        Ok(b) => b,
        Err(e) => {
            result.errors.push(format!("enumerate consumer binds: {e}"));
            return result;
        }
    };
    if binds.is_empty() {
        result.no_consumers_found = true;
        return result;
    }

    for bind in &binds {
        // Probe the bind ROOT as seen inside the consumer.
        match runtime
            .probe_path(&bind.container_id, &bind.container_target, health_timeout)
            .await
        {
            Ok(ConsumerProbe::Ok) => result.healthy.push(bind.container_name.clone()),
            Ok(ConsumerProbe::Stale) => {
                // Guard: only remediate a stale bind when the HOST mount is
                // healthy. A host-wide outage makes every consumer stale;
                // restarting then is pointless and stormy.
                if !host_healthy(&bind.host_source) {
                    result.skipped_host_stale.push(bind.container_name.clone());
                    continue;
                }
                match runtime.restart(&bind.container_id).await {
                    Ok(()) => match runtime
                        .probe_path(&bind.container_id, &bind.container_target, health_timeout)
                        .await
                    {
                        Ok(ConsumerProbe::Ok) => result.recovered.push(bind.container_name.clone()),
                        Ok(ConsumerProbe::Stale) => {
                            result.still_stale.push(bind.container_name.clone())
                        }
                        Err(e) => {
                            result.still_stale.push(bind.container_name.clone());
                            result
                                .errors
                                .push(format!("re-probe {}: {e}", bind.container_name));
                        }
                    },
                    Err(e) => {
                        result.still_stale.push(bind.container_name.clone());
                        result
                            .errors
                            .push(format!("restart {}: {e}", bind.container_name));
                    }
                }
            }
            Err(e) => result
                .errors
                .push(format!("probe {}: {e}", bind.container_name)),
        }
    }

    result
}

/// Production [`ContainerRuntime`] that shells `docker` via
/// `plugin_toolkit::process::Command`. All runtime shell-outs are confined here
/// so the sweep logic stays runtime-agnostic and mockable.
pub struct DockerCli;

/// Tab-separated one-line-per-bind format emitted by `docker inspect`:
/// `id\tname\tsource\tdestination` for every `bind`-type mount.
const DOCKER_BIND_FORMAT: &str = "{{range .Mounts}}{{if eq .Type \"bind\"}}{{$.Id}}\t{{$.Name}}\t{{.Source}}\t{{.Destination}}\n{{end}}{{end}}";

#[orca_async]
impl ContainerRuntime for DockerCli {
    async fn binds_under(&self, watch: &[String]) -> Result<Vec<ConsumerBind>, NfsError> {
        // Running container ids first, then inspect their bind mounts.
        let out = Command::new("docker")
            .arg("ps")
            .arg("--no-trunc")
            .arg("--format")
            .arg("{{.ID}}")
            .output()
            .await
            .map_err(NfsError::Read)?;
        if !out.status.success {
            return Err(NfsError::Read(std::io::Error::other(format!(
                "docker ps exit {:?}: {}",
                out.status.code,
                String::from_utf8_lossy(&out.stderr).trim()
            ))));
        }
        let ids: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        // `Command::arg` consumes `self` (builder), so fold the ids in.
        let mut inspect = Command::new("docker")
            .arg("inspect")
            .arg("--format")
            .arg(DOCKER_BIND_FORMAT);
        for id in &ids {
            inspect = inspect.arg(id);
        }
        let out = inspect.output().await.map_err(NfsError::Read)?;
        if !out.status.success {
            return Err(NfsError::Read(std::io::Error::other(format!(
                "docker inspect exit {:?}: {}",
                out.status.code,
                String::from_utf8_lossy(&out.stderr).trim()
            ))));
        }
        Ok(parse_docker_binds(
            &String::from_utf8_lossy(&out.stdout),
            watch,
        ))
    }

    async fn probe_path(
        &self,
        id: &str,
        path: &str,
        timeout: Duration,
    ) -> Result<ConsumerProbe, NfsError> {
        let fut = Command::new("docker")
            .arg("exec")
            .arg(id)
            .arg("stat")
            .arg("--")
            .arg(path)
            .output();
        match plugin_toolkit::time::timeout(timeout, fut).await {
            // In-container `stat` hung past the budget → stale (same rule as the
            // host probe's timeout→stale).
            None => Ok(ConsumerProbe::Stale),
            Some(Err(e)) => Err(NfsError::Read(e)),
            Some(Ok(out)) if out.status.success => Ok(ConsumerProbe::Ok),
            Some(Ok(out)) => {
                if classify_stat_failure(&String::from_utf8_lossy(&out.stderr)) == "stale" {
                    Ok(ConsumerProbe::Stale)
                } else {
                    Err(NfsError::Read(std::io::Error::other(
                        String::from_utf8_lossy(&out.stderr).trim().to_string(),
                    )))
                }
            }
        }
    }

    async fn restart(&self, id: &str) -> Result<(), NfsError> {
        let out = Command::new("docker")
            .arg("restart")
            .arg(id)
            .output()
            .await
            .map_err(NfsError::Read)?;
        if out.status.success {
            Ok(())
        } else {
            Err(NfsError::Read(std::io::Error::other(format!(
                "docker restart {id} exit {:?}: {}",
                out.status.code,
                String::from_utf8_lossy(&out.stderr).trim()
            ))))
        }
    }
}

/// Parse the `id\tname\tsource\tdestination` lines emitted by
/// [`DOCKER_BIND_FORMAT`], keeping only binds whose host source falls under a
/// watched prefix. Pulled out so it's testable without Docker.
fn parse_docker_binds(raw: &str, watch: &[String]) -> Vec<ConsumerBind> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split('\t');
        let (Some(id), Some(name), Some(source), Some(dest)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if !path_under_watch(source, watch) {
            continue;
        }
        out.push(ConsumerBind {
            container_id: id.to_string(),
            // docker prefixes names with '/'; strip it for reporting.
            container_name: name.trim_start_matches('/').to_string(),
            host_source: source.to_string(),
            container_target: dest.to_string(),
        });
    }
    out
}

// ── nfs option grammar ──────────────────────────────────────────────────────
//
// The nfs backend owns the grammar of its own mount options. `parse_nfs_options`
// turns the raw comma string a `MountSpec` carries into a typed
// `OptionSet::Nfs`, rejecting anything malformed or self-contradictory at declare
// time rather than at mount time. `normalize_nfs_source` canonicalizes the
// `host:/export` form. `render_option_set` (owned by the storage domain) is the
// inverse — the two round-trip.

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

/// Parse a raw comma-separated nfs option string into a typed [`OptionSet::Nfs`],
/// enforcing the backend's grammar:
///   * `vers` must be one of [`VALID_NFS_VERS`];
///   * `hard` and `soft` are mutually exclusive (declaring both is rejected);
///   * `timeo`/`retrans`/`actimeo`/`rsize`/`wsize` must parse and sit in sane
///     bounds;
///   * `_netdev` sets the netdev flag;
///   * every other `key` / `key=value` token is preserved verbatim in `extra`,
///     so a legal-but-untyped option (`nconnect=4`, `nofail`, `ro`) rides
///     through without the backend having to enumerate the whole kernel grammar.
fn parse_nfs_options(raw: Option<&str>) -> Result<OptionSet, StorageError> {
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
    for tok in raw.split(',') {
        let tok = tok.trim();
        if tok.is_empty() {
            continue;
        }
        let (key, value) = match tok.split_once('=') {
            Some((k, v)) => (k.trim(), Some(v.trim())),
            None => (tok, None),
        };
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
            _ => extra.push(tok.to_string()),
        }
    }

    if hard == Some(true) && soft == Some(true) {
        return Err(StorageError::Other(
            "nfs options `hard` and `soft` are mutually exclusive".into(),
        ));
    }

    Ok(OptionSet::Nfs {
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

    /// Parse + validate an nfs mount spec into a typed [`OptionSet::Nfs`],
    /// rejecting malformed or conflicting options (bad `vers`, `hard`+`soft`,
    /// out-of-range numerics) at declare time. The source (and any failover
    /// sources) are normalized to canonical `host:/export` form.
    async fn validate_spec(&self, spec: &MountSpec) -> Result<NormalizedSpec, StorageError> {
        let options = parse_nfs_options(spec.options.as_deref())?;
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
            options,
            credential: spec.credential.clone(),
            remount_policy: spec.remount_policy.clone(),
            enabled: spec.enabled,
        })
    }

    /// Emit the canonical comma-separated nfs option string autofs's `-fstype`
    /// line consumes. Delegates to the storage domain's canonical renderer so the
    /// grammar has a single source of truth and round-trips with `validate_spec`.
    fn render_options(&self, spec: &NormalizedSpec) -> String {
        render_option_set(&spec.options)
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
        // the consumer-aware bind-mount sweep (guarded on host-health), using the
        // production `DockerCli` runtime. `RecoverOutcome` is a closed toolkit
        // type with no consumer fields, so consumer results are folded into its
        // existing vecs with a `consumer:` tag so a caller can still see them.
        let runtime = DockerCli;
        let mut r = recover_stale_with_consumers(&runtime, watch, "", health_timeout)
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
    async fn check_health_returns_error_for_missing_path() {
        let s = check_health("/definitely/not/here/orca_nfs_test", Duration::from_secs(5)).await;
        assert!(s.starts_with("error:"));
    }

    #[test]
    fn classify_stat_failure_maps_estale_to_stale() {
        // Fast ESTALE — the consumer-bind failure mode — must classify stale so
        // the force-release/remount recovery fires (regression: it used to
        // return "error: …").
        assert_eq!(
            classify_stat_failure("stat: cannot statx '/mnt/pool': Stale file handle"),
            "stale"
        );
        // Case-insensitive.
        assert_eq!(classify_stat_failure("STALE FILE HANDLE"), "stale");
    }

    #[test]
    fn classify_stat_failure_keeps_other_errors_as_error() {
        let s = classify_stat_failure("stat: cannot statx '/mnt/pool': No such file or directory");
        assert!(s.starts_with("error:"), "got: {s}");
        assert!(s.contains("No such file or directory"));
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

    // Linux-only paths (`read_mounts`, `list`, `release`) all hit /proc/mounts
    // which doesn't exist on macOS. Exercise the Err path on non-Linux so
    // those functions still get coverage in CI runners that aren't Linux.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn read_mounts_errors_when_proc_mounts_absent() {
        let err = read_mounts().unwrap_err();
        assert!(matches!(err, NfsError::Read(_)));
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn list_propagates_read_mounts_failure() {
        let res = list(&[], "", Duration::from_secs(1)).await;
        assert!(res.is_err());
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn release_propagates_read_mounts_failure() {
        // Both force modes must surface the enumeration error.
        assert!(release("", "", false).await.is_err());
        assert!(release("", "", true).await.is_err());
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn recover_stale_propagates_read_mounts_failure() {
        // Initial enumeration failure is the one fatal path.
        let res = recover_stale(&[], "", Duration::from_secs(1)).await;
        assert!(res.is_err());
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

    // ── consumer-aware bind-mount staleness (Part B) ──────────────────────────

    #[test]
    fn parse_docker_binds_filters_to_watched_sources() {
        // id\tname\tsource\tdest — three binds, only two under /mnt/pool.
        let raw = "\
abc\t/downloader\t/mnt/pool/downloads\t/data
def\t/media\t/mnt/pool/data/media\t/media
ghi\t/other\t/srv/other\t/srv
";
        let watch = vec!["/mnt/pool".to_string()];
        let binds = parse_docker_binds(raw, &watch);
        assert_eq!(binds.len(), 2, "only /mnt/pool binds");
        assert_eq!(binds[0].container_name, "downloader", "'/' stripped");
        assert_eq!(binds[0].host_source, "/mnt/pool/downloads");
        assert_eq!(binds[0].container_target, "/data");
        assert_eq!(binds[1].container_target, "/media");
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
            },
            Mount {
                device: "srv:/pool/data".into(),
                mountpoint: "/mnt/pool/data".into(),
                fstype: "nfs4".into(),
                health: Some("stale".into()),
            },
        ];
        // Longest covering mount for this source is /mnt/pool/data (stale).
        assert!(!host_source_healthy("/mnt/pool/data/media", &mounts));
        // Covered only by /mnt/pool (ok).
        assert!(host_source_healthy("/mnt/pool/downloads", &mounts));
        // Uncovered → treated as unhealthy (guard errs toward not restarting).
        assert!(!host_source_healthy("/srv/elsewhere", &mounts));
    }

    // ── mocked container runtime ──────────────────────────────────────────────

    /// Scripted [`ContainerRuntime`] — no Docker. Records restarts and returns a
    /// probe verdict per container that can flip after a restart (models a
    /// consumer coming back healthy once re-bound).
    struct MockRuntime {
        binds: Vec<ConsumerBind>,
        /// container_id → (probe before restart, probe after restart).
        probes: std::collections::HashMap<String, (ConsumerProbe, ConsumerProbe)>,
        restarted: std::sync::Mutex<Vec<String>>,
        restart_fails: std::collections::HashSet<String>,
        enumerate_fails: bool,
    }

    impl MockRuntime {
        fn new(binds: Vec<ConsumerBind>) -> Self {
            Self {
                binds,
                probes: std::collections::HashMap::new(),
                restarted: std::sync::Mutex::new(Vec::new()),
                restart_fails: std::collections::HashSet::new(),
                enumerate_fails: false,
            }
        }
    }

    #[plugin_toolkit::async_trait::async_trait]
    impl ContainerRuntime for MockRuntime {
        async fn binds_under(&self, _watch: &[String]) -> Result<Vec<ConsumerBind>, NfsError> {
            if self.enumerate_fails {
                return Err(NfsError::Read(std::io::Error::other("boom")));
            }
            Ok(self.binds.clone())
        }
        async fn probe_path(
            &self,
            id: &str,
            _path: &str,
            _timeout: Duration,
        ) -> Result<ConsumerProbe, NfsError> {
            let (before, after) = self
                .probes
                .get(id)
                .copied()
                .unwrap_or((ConsumerProbe::Ok, ConsumerProbe::Ok));
            let already_restarted = self.restarted.lock().unwrap().iter().any(|r| r == id);
            Ok(if already_restarted { after } else { before })
        }
        async fn restart(&self, id: &str) -> Result<(), NfsError> {
            if self.restart_fails.contains(id) {
                return Err(NfsError::Read(std::io::Error::other("restart failed")));
            }
            self.restarted.lock().unwrap().push(id.to_string());
            Ok(())
        }
    }

    fn bind(id: &str, name: &str, source: &str, target: &str) -> ConsumerBind {
        ConsumerBind {
            container_id: id.into(),
            container_name: name.into(),
            host_source: source.into(),
            container_target: target.into(),
        }
    }

    #[tokio::test]
    async fn consumer_sweep_restarts_when_host_healthy_and_consumer_stale() {
        // The incident: host healthy, consumer bind ROOT ESTALE → restart, and
        // it comes back healthy after re-bind.
        let mut rt = MockRuntime::new(vec![bind(
            "c1",
            "downloader",
            "/mnt/pool/downloads",
            "/data",
        )]);
        rt.probes
            .insert("c1".into(), (ConsumerProbe::Stale, ConsumerProbe::Ok));

        let res =
            recover_stale_consumers(&rt, &["/mnt/pool".into()], Duration::from_secs(1), |_| {
                true // host healthy
            })
            .await;

        assert_eq!(res.recovered, vec!["downloader".to_string()]);
        assert!(res.still_stale.is_empty());
        assert!(res.skipped_host_stale.is_empty());
        assert_eq!(*rt.restarted.lock().unwrap(), vec!["c1".to_string()]);
    }

    #[tokio::test]
    async fn consumer_sweep_skips_restart_during_host_outage() {
        // Guard: consumer ESTALE but the HOST mount is also stale → do NOT
        // restart (host-wide outage; a restart would not help and could storm).
        let mut rt = MockRuntime::new(vec![bind("c1", "media", "/mnt/pool/data/media", "/media")]);
        rt.probes
            .insert("c1".into(), (ConsumerProbe::Stale, ConsumerProbe::Ok));

        let res = recover_stale_consumers(
            &rt,
            &["/mnt/pool".into()],
            Duration::from_secs(1),
            |_| false, // host UNhealthy
        )
        .await;

        assert_eq!(res.skipped_host_stale, vec!["media".to_string()]);
        assert!(res.recovered.is_empty());
        assert!(
            rt.restarted.lock().unwrap().is_empty(),
            "must not restart during host outage"
        );
    }

    #[tokio::test]
    async fn consumer_sweep_leaves_healthy_consumers_alone() {
        let mut rt = MockRuntime::new(vec![bind("c1", "healthy-app", "/mnt/pool/downloads", "/d")]);
        rt.probes
            .insert("c1".into(), (ConsumerProbe::Ok, ConsumerProbe::Ok));
        let res =
            recover_stale_consumers(&rt, &["/mnt/pool".into()], Duration::from_secs(1), |_| true)
                .await;
        assert_eq!(res.healthy, vec!["healthy-app".to_string()]);
        assert!(rt.restarted.lock().unwrap().is_empty(), "idempotent");
    }

    #[tokio::test]
    async fn consumer_sweep_reports_still_stale_when_restart_does_not_clear() {
        let mut rt = MockRuntime::new(vec![bind("c1", "stuck", "/mnt/pool/downloads", "/d")]);
        // Stays stale even after restart.
        rt.probes
            .insert("c1".into(), (ConsumerProbe::Stale, ConsumerProbe::Stale));
        let res =
            recover_stale_consumers(&rt, &["/mnt/pool".into()], Duration::from_secs(1), |_| true)
                .await;
        assert_eq!(res.still_stale, vec!["stuck".to_string()]);
        assert!(res.recovered.is_empty());
    }

    #[tokio::test]
    async fn consumer_sweep_records_restart_failure() {
        let mut rt = MockRuntime::new(vec![bind("c1", "flaky", "/mnt/pool/downloads", "/d")]);
        rt.probes
            .insert("c1".into(), (ConsumerProbe::Stale, ConsumerProbe::Ok));
        rt.restart_fails.insert("c1".into());
        let res =
            recover_stale_consumers(&rt, &["/mnt/pool".into()], Duration::from_secs(1), |_| true)
                .await;
        assert_eq!(res.still_stale, vec!["flaky".to_string()]);
        assert!(res.errors.iter().any(|e| e.contains("restart flaky")));
    }

    #[tokio::test]
    async fn consumer_sweep_no_consumers_is_noop() {
        let rt = MockRuntime::new(vec![]);
        let res =
            recover_stale_consumers(&rt, &["/mnt/pool".into()], Duration::from_secs(1), |_| true)
                .await;
        assert!(res.no_consumers_found);
        assert!(res.recovered.is_empty());
    }

    #[tokio::test]
    async fn consumer_sweep_enumerate_failure_is_recorded_not_fatal() {
        let mut rt = MockRuntime::new(vec![]);
        rt.enumerate_fails = true;
        let res =
            recover_stale_consumers(&rt, &["/mnt/pool".into()], Duration::from_secs(1), |_| true)
                .await;
        assert!(!res.no_consumers_found);
        assert!(res.errors.iter().any(|e| e.contains("enumerate")));
    }

    #[test]
    fn consumer_recover_result_round_trips_through_serde() {
        let c = ConsumerRecoverResult {
            healthy: vec!["a".into()],
            recovered: vec!["b".into()],
            skipped_host_stale: vec!["c".into()],
            still_stale: vec!["d".into()],
            errors: vec!["restart d: boom".into()],
            no_consumers_found: false,
        };
        let s = serde_json::to_string(&c).unwrap();
        let back: ConsumerRecoverResult = serde_json::from_str(&s).unwrap();
        assert_eq!(back.healthy, c.healthy);
        assert_eq!(back.recovered, c.recovered);
        assert_eq!(back.skipped_host_stale, c.skipped_host_stale);
        assert_eq!(back.still_stale, c.still_stale);
        assert_eq!(back.errors, c.errors);
        assert!(!back.no_consumers_found);

        // And nested inside RecoverResult.
        let r = RecoverResult {
            consumers: Some(c),
            ..Default::default()
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("consumers"));
        let back: RecoverResult = serde_json::from_str(&s).unwrap();
        assert!(back.consumers.is_some());
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
        match set {
            OptionSet::Nfs {
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
            } => {
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
            other => panic!("expected OptionSet::Nfs, got {other:?}"),
        }
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
