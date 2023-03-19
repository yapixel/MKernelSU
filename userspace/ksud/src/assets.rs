use anyhow::{bail, Result};
use const_format::concatcp;
use rust_embed::RustEmbed;

use crate::{defs::BINARY_DIR, utils};
use crate::restorecon::setsyscon;

pub const RESETPROP_PATH: &str = concatcp!(BINARY_DIR, "resetprop");
pub const BUSYBOX_PATH: &str = concatcp!(BINARY_DIR, "busybox");

#[cfg(target_arch = "aarch64")]
#[derive(RustEmbed)]
#[folder = "bin/aarch64"]
struct Asset;

#[cfg(target_arch = "x86_64")]
#[derive(RustEmbed)]
#[folder = "bin/x86_64"]
struct Asset;

pub fn ensure_binaries() -> Result<()> {
    for file in Asset::iter() {
        utils::ensure_binary(
            format!("{BINARY_DIR}{file}"),
            &Asset::get(&file).unwrap().data,
        )?
    }
    Ok(())
}

pub fn extract_su() -> Result<()> {
    let path = crate::ksu::get_path();
    if let Err(e) = path {
        bail!("failed to get path {e}")
    }
    let path = path.unwrap();
    let p = format!("{}/bin/su", path);
    if let Err(e) = utils::ensure_binary(
        &p,
        &Asset::get("su").unwrap().data,
    ) {
        bail!("failed to extract su binary {e}")
    }
    if let Err(e) = setsyscon(&p) {
        bail!("failed to set system context {e}")
    }
    Ok(())
}
