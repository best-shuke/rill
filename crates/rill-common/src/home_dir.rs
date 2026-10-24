//! Process-wide rill home directory.
//!
//! `set_home_dir` must be called once at startup (from `-d` CLI flag) before
//! any of the path helpers in `rill-config` or `rill-rules` are invoked.
//! After that, all resource-path helpers (`default_geoip_path`,
//! `default_asn_path`, `default_geosite_candidates`, …) resolve under this
//! directory instead of the XDG / `$HOME/.config` fallback.

use std::path::PathBuf;

static RILL_HOME_DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Set the process-wide rill home directory from the `-d` CLI flag.
///
/// First write wins; subsequent calls are silently ignored (idempotent).
/// Must be called before any path helper that delegates to `rill_home_dir`.
pub fn set_home_dir(dir: PathBuf) {
    let _ = RILL_HOME_DIR.set(dir);
}

/// Return the stored home directory, or `None` if `set_home_dir` was never
/// called.  Callers should fall back to the XDG / `$HOME/.config` chain when
/// this returns `None`.
pub fn rill_home_dir() -> Option<PathBuf> {
    RILL_HOME_DIR.get().cloned()
}

/// The XDG fallback chain used when no `-d` home applies:
/// `$XDG_CONFIG_HOME/rill`, `$HOME/.config/rill`, `./rill` last resort.
/// Shared so crates that cannot depend on `rill-config` (e.g.
/// `rill-proxy` — dependency cycle) resolve relative resource paths the
/// same way the config loader does.
pub fn xdg_home_dir() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("rill")
}

/// The effective rill home directory: the `-d` override when set, else
/// [`xdg_home_dir`].
pub fn resolved_home_dir() -> PathBuf {
    rill_home_dir().unwrap_or_else(xdg_home_dir)
}

#[cfg(test)]
mod tests {
    // OnceLock is process-global, so we cannot meaningfully test set/get in
    // isolation across parallel test threads.  The compile-time check below is
    // enough to confirm the API surface is correct.
    use super::*;
    use std::path::PathBuf;

    #[allow(dead_code, reason = "compile-time shape check, never executed")]
    fn _shape_check() {
        set_home_dir(PathBuf::from("/tmp/rill"));
        let _: Option<PathBuf> = rill_home_dir();
    }
}
