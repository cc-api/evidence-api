#![allow(non_camel_case_types)]
use crate::cc_type::*;
use hashbrown::HashMap;

pub struct Tdx {}

// TDX version ID
#[derive(Clone, Eq, Hash, PartialEq)]
pub enum TdxVersion {
    TDX_1_0,
    TDX_1_5,
}

// TDX version ID to version string map
lazy_static! {
    pub static ref TDX_VERSION_MAP: HashMap<TdxVersion, String> = {
        let mut map: HashMap<TdxVersion, String> = HashMap::new();
        map.insert(TdxVersion::TDX_1_0, "1.0".to_string());
        map.insert(TdxVersion::TDX_1_5, "1.5".to_string());
        map
    };
}

// TDX version ID to device path string map
lazy_static! {
    pub static ref TDX_DEVICE_NODE_MAP: HashMap<TdxVersion, String> = {
        let mut map: HashMap<TdxVersion, String> = HashMap::new();
        map.insert(TdxVersion::TDX_1_0, TEE_TDX_1_0_PATH.to_string());
        map.insert(TdxVersion::TDX_1_5, TEE_TDX_1_5_PATH.to_string());
        map
    };
}

// quote and tdreport length
pub const REPORT_DATA_LEN: u32 = 64;
pub const TDX_REPORT_LEN: u32 = 1024;
pub const TDX_QUOTE_LEN: usize = 4 * 4096;
