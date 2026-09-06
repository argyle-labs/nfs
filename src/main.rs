//! Dynamic (subprocess) entrypoint for the nfs plugin.
//!
//! Serves this plugin over the orca socket via the typed `Plugin` builder. The plugin is a
//! `[[bin]]`, owns no runtime, and reaches orca only through the socket.
plugin_toolkit::instrument::bootstrap!();
use plugin_toolkit::plugin::Plugin;

fn main() -> plugin_toolkit::anyhow::Result<()> {
    Plugin::named("nfs")
        .version(env!("CARGO_PKG_VERSION"))
        .storage(nfs::NfsBackend::new("nfs"))
        .serve()
}
