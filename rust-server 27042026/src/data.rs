pub static DEFAULT_AVATAR_PNG: &[u8] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../data/avatar.png"));

pub static SEED_MODULE_BIN: &[u8] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../data/module.bin"));

pub static KEY_BIN: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../data/key.bin"));

const _: () = assert!(DEFAULT_AVATAR_PNG.len() == 28_823);
const _: () = assert!(SEED_MODULE_BIN.len() == 385_360);
const _: () = assert!(KEY_BIN.len() == 80);
