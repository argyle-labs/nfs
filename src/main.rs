//! Dynamic (subprocess) entrypoint for the nfs plugin.
//!
//! The toolkit's `serve_storage_plugin!` emits `fn main`, serving this plugin over the orca
//! socket. The plugin is a `[[bin]]`, owns no runtime, and reaches orca only
//! through the socket.
plugin_toolkit::serve_storage_plugin! {
    name: "nfs",
    target_compat: "any",
    backend: nfs::NfsBackend::new("nfs"),
}
