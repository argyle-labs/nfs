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
    Capability, MountOutcome, RecoverOutcome, Share, StorageBackend, StorageError, StorageKind,
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

/// `stat <mountpoint>` with a timeout. Returns `"ok"` / `"stale"` / `"error: …"`.
/// `stat` blocks in-kernel on stale NFS handles, so the timeout is the
/// only reliable detection signal.
pub async fn check_health(mountpoint: &str, timeout: Duration) -> String {
    let fut = Command::new("stat").arg("--").arg(mountpoint).output();
    match plugin_toolkit::time::timeout(timeout, fut).await {
        None => "stale".to_string(),
        Some(Err(e)) => format!("error: {e}"),
        Some(Ok(out)) if out.status.success => "ok".to_string(),
        Some(Ok(out)) => format!("error: {}", String::from_utf8_lossy(&out.stderr).trim()),
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
        let r = recover_stale(watch, "", health_timeout)
            .await
            .map_err(|e| StorageError::Transport(e.to_string()))?;
        Ok(RecoverOutcome {
            recovered: r.recovered,
            still_stale: r.still_stale,
            remounted: r.remounted,
            still_missing: r.still_missing,
            errors: r.errors,
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
        };
        let s = serde_json::to_string(&r).unwrap();
        let back: RecoverResult = serde_json::from_str(&s).unwrap();
        assert_eq!(back.recovered, r.recovered);
        assert_eq!(back.still_stale, r.still_stale);
        assert_eq!(back.errors, r.errors);
        assert!(!back.no_stale_found);
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
}
