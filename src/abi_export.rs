// The domain surface crosses this FFI boundary as opaque JSON — the designated
// JSON dispatch seam, identical to orca's `plugin-loader` and the storage
// crate's `StorageProxy`. The payload type is aliased (`sj`) at this one seam,
// exactly as the loader aliases it, and the workspace disallowed-types lint is
// suppressed for this file only.
#![allow(clippy::disallowed_types)]

//! ABI-stable cdylib export for the nfs storage backend.
//!
//! Builds and exports the single [`PluginModRef`] root module orca's
//! `plugin-loader` `dlopen`s. nfs is a **backend-only** plugin: it carries no
//! `#[orca_tool]` inventory, so `manifest()` is the empty array and `invoke()`
//! does **not** route through `dispatch::dispatch` (there is no tool to find).
//! Instead `backends()` advertises one storage [`BackendDef`] and `invoke()`
//! routes the storage domain's proxied operations — `list_shares` / `unmount` /
//! `recover_stale` — directly to the in-process [`NfsBackend`] methods that the
//! storage crate's `StorageProxy` marshals across this boundary.
//!
//! Only the entrypoint + metadata cross as `StableAbi` types; the backend
//! descriptor and every op's args/result cross as JSON, against the exact same
//! typed wire structs `storage::StorageProxy` serializes — no opaque `Value`.

use std::sync::OnceLock;
use std::time::Duration;

// The `#[export_root_module]` attribute expands to bare `::abi_stable` paths in
// this crate's root, so `abi_stable` must be a direct dependency — it is a
// genuinely-external (non-orca) crate. Pinned to the toolkit's version so the
// layout hash the loader checks matches.
use abi_stable::export_root_module;
use abi_stable::prefix_type::PrefixTypeTrait;
use abi_stable::std_types::{RErr, ROk, RResult, RStr, RString};
use plugin_toolkit::abi::{BackendDef, PluginMod, PluginModRef};
// The JSON dispatch payload helpers, named once here at the designated seam.
use plugin_toolkit::serde::{Deserialize, Serialize};
use plugin_toolkit::serde_json as sj;
use plugin_toolkit::storage::{MountOutcome, RecoverOutcome, Share, StorageBackend};
use plugin_toolkit::tokio::runtime::{Builder, Runtime};

use crate::NfsBackend;

/// The backend instance name. Doubles as the storage-registry key and the tail
/// of [`INVOKE_PREFIX`]. Keep in sync with [`NfsBackend::default`].
const BACKEND_NAME: &str = "nfs";

/// Tool-name prefix the storage `StorageProxy` invokes under. The loader builds
/// a thunk that calls `"{INVOKE_PREFIX}.{op}"` for each proxied op
/// (`list_shares` / `unmount` / `recover_stale`); `invoke()` below strips this
/// prefix and routes the bare op to the in-process [`NfsBackend`].
const INVOKE_PREFIX: &str = "storage.__backend.nfs";

extern "C" fn plugin_semver() -> RString {
    RString::from(env!("CARGO_PKG_VERSION"))
}

extern "C" fn target_software() -> RString {
    RString::from("nfs")
}

extern "C" fn target_compat() -> RString {
    // nfs reads the kernel mount table (nfs/nfs4/cifs/smbfs) rather than a
    // versioned external service, so there is no upstream version to pin.
    RString::from("any")
}

extern "C" fn orca_compat() -> RString {
    RString::from(">=0.0.8, <0.1.0")
}

/// nfs exposes zero `#[orca_tool]`s — it is a pure storage backend. The manifest
/// is therefore the empty array, identical to what the loader's per-field
/// default synthesizes; the plugin's whole surface crosses via [`backends`].
extern "C" fn manifest() -> RString {
    RString::from("[]")
}

/// The single storage backend this plugin contributes. `kind`/`capabilities`
/// mirror [`NfsBackend`]'s `StorageKind::NetworkShare` +
/// `List`/`Unmount`/`RecoverStale`, stringified into the domain's wire vocab the
/// loader's `parse_kind`/`parse_capability` accept. `invoke_prefix` is the
/// family the `StorageProxy` calls back through.
extern "C" fn backends() -> RString {
    let def = BackendDef {
        domain: "storage".to_string(),
        name: BACKEND_NAME.to_string(),
        kind: "network_share".to_string(),
        endpoint: "nfs://local".to_string(),
        capabilities: vec![
            "list".to_string(),
            "unmount".to_string(),
            "recover_stale".to_string(),
        ],
        invoke_prefix: INVOKE_PREFIX.to_string(),
        ..Default::default()
    };
    RString::from(sj::to_string(&[def]).unwrap_or_else(|_| "[]".to_string()))
}

/// Shared multi-thread runtime driving the async [`NfsBackend`] methods behind
/// the synchronous FFI `invoke`. Built once, kept for the process lifetime.
fn runtime() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("build nfs plugin tokio runtime")
    })
}

// ── Proxy wire-args ─────────────────────────────────────────────────────────
// These mirror `storage::StorageProxy`'s private wire structs byte-for-byte so
// each op deserializes against the exact shape the proxy serializes. `list_shares`
// sends `{}` (NoArgs) and needs no struct.

#[derive(Serialize, Deserialize)]
#[serde(crate = "plugin_toolkit::serde")]
struct UnmountArgs {
    target: String,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "plugin_toolkit::serde")]
struct RecoverArgs {
    watch: Vec<String>,
    health_timeout_secs: f64,
}

/// Encode a serializable result back across the boundary as `ROk(json)`.
fn ok_json<T: Serialize>(value: &T) -> RResult<RString, RString> {
    match sj::to_string(value) {
        Ok(s) => ROk(RString::from(s)),
        Err(e) => RErr(RString::from(format!("failed to encode result: {e}"))),
    }
}

extern "C" fn invoke(name: RStr<'_>, args_json: RStr<'_>) -> RResult<RString, RString> {
    let Some(op) = name.as_str().strip_prefix(INVOKE_PREFIX).and_then(|rest| {
        // Expect exactly "{INVOKE_PREFIX}.{op}".
        rest.strip_prefix('.')
    }) else {
        return RErr(RString::from(format!(
            "tool '{}' is not in this plugin's '{INVOKE_PREFIX}.*' namespace",
            name.as_str()
        )));
    };

    let backend = NfsBackend::new(BACKEND_NAME);
    let rt = runtime();

    match op {
        "list_shares" => match rt.block_on(backend.list_shares()) {
            Ok(shares) => ok_json::<Vec<Share>>(&shares),
            Err(e) => RErr(RString::from(format!("{e}"))),
        },
        "unmount" => {
            let args: UnmountArgs = match sj::from_str(args_json.as_str()) {
                Ok(v) => v,
                Err(e) => return RErr(RString::from(format!("invalid unmount args: {e}"))),
            };
            match rt.block_on(backend.unmount(&args.target)) {
                Ok(outcome) => ok_json::<MountOutcome>(&outcome),
                Err(e) => RErr(RString::from(format!("{e}"))),
            }
        }
        "recover_stale" => {
            let args: RecoverArgs = match sj::from_str(args_json.as_str()) {
                Ok(v) => v,
                Err(e) => return RErr(RString::from(format!("invalid recover_stale args: {e}"))),
            };
            let timeout = Duration::from_secs_f64(args.health_timeout_secs);
            match rt.block_on(backend.recover_stale(&args.watch, timeout)) {
                Ok(outcome) => ok_json::<RecoverOutcome>(&outcome),
                Err(e) => RErr(RString::from(format!("{e}"))),
            }
        }
        other => RErr(RString::from(format!(
            "nfs backend has no operation '{other}'"
        ))),
    }
}

/// Declared SQL tables: none yet (this plugin owns no plugin-scoped tables).
/// Empty declaration matches what orca synthesizes for a plugin predating the
/// field; a stateful plugin would return a real SchemaDecl here.
extern "C" fn schemas() -> RString {
    RString::from(r#"{"namespace":"","tables":[]}"#)
}

#[export_root_module]
fn export() -> PluginModRef {
    PluginMod {
        plugin_semver,
        target_software,
        target_compat,
        orca_compat,
        manifest,
        invoke,
        backends,
        schemas,
    }
    .leak_into_prefix()
}
