//! Updates and verifies the generated Chromium Root Store snapshot.

use std::{
    env,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};

mod component;
mod generator;

fn main() -> Result<()> {
    let root = project_root()?;
    let mut args = env::args().skip(1);
    let command = args
        .next()
        .context("expected one of: update, generate, check")?;
    ensure_no_extra_args(args)?;

    match command.as_str() {
        "update" => component::update(&root),
        "generate" => generate(&root),
        "check" => component::check(&root),
        _ => bail!("unknown command {command:?}; expected update, generate, or check"),
    }
}

/// Rejects misspelled or accidentally appended command arguments.
fn ensure_no_extra_args(mut args: impl Iterator<Item = String>) -> Result<()> {
    ensure!(args.next().is_none(), "too many command-line arguments");
    Ok(())
}

/// Resolves the workspace root from the compile-time maintenance package manifest path.
fn project_root() -> Result<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .context("maintenance package must be located below the workspace root")
}

/// Regenerates the static Rust data from the checked-in signed payload.
fn generate(root: &Path) -> Result<()> {
    let generated = generator::generate(root)?;
    let changed = generator::write_generated_source(root, &generated.source)?;
    let action = if changed { "updated" } else { "checked" };
    println!(
        "{action} Chrome Root Store version {} ({} anchors, {} IDs)",
        generated.root_store_version, generated.anchor_count, generated.id_count
    );
    Ok(())
}
