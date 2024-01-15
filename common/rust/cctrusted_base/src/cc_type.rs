use hashbrown::HashMap;

// supported TEE types
#[derive(Clone, Eq, Hash, PartialEq, Debug)]
pub enum TeeType {
    PLAIN = -1,
    TPM = 0,
    TDX = 1,
    SEV = 2,
    CCA = 3,
}

// TEE type to type name string mapping
lazy_static! {
    pub static ref TEE_NAME_MAP: HashMap<TeeType, String> = {
        let mut map: HashMap<TeeType, String> = HashMap::new();
        map.insert(TeeType::PLAIN, "PLAIN".to_string());
        map.insert(TeeType::TDX, "TDX".to_string());
        map.insert(TeeType::SEV, "SEV".to_string());
        map.insert(TeeType::CCA, "CCA".to_string());
        map.insert(TeeType::TPM, "TPM".to_string());
        map
    };
}

// public known device node path
pub const TEE_TPM_PATH: &str = "/dev/tpm0";
pub const TEE_TDX_1_0_PATH: &str = "/dev/tdx-guest";
pub const TEE_TDX_1_5_PATH: &str = "/dev/tdx_guest";
pub const TEE_SEV_PATH: &str = "/dev/sev-guest";
pub const TEE_CCA_PATH: &str = "";

// holds the TEE type info
#[derive(Clone)]
pub struct CcType {
    pub tee_type: TeeType,
    pub tee_type_str: String,
}
