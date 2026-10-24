//! Exposes the reported binary version as `RILL_VERSION`.
//!
//! Normally this is just `CARGO_PKG_VERSION`. The rolling alpha prerelease
//! workflow sets `RILL_VERSION_SUFFIX` (e.g. `-alpha+abc1234`) so an alpha
//! binary is identifiable in `rill -v` / `rill --version` (issue #565).

fn main() {
    println!("cargo:rerun-if-env-changed=RILL_VERSION_SUFFIX");
    let base = std::env::var("CARGO_PKG_VERSION").expect("cargo sets CARGO_PKG_VERSION");
    let suffix = std::env::var("RILL_VERSION_SUFFIX").unwrap_or_default();
    println!("cargo:rustc-env=RILL_VERSION={base}{}", suffix.trim());
}
