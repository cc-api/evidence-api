use core::convert::From;

// supported TEE types
#[derive(Clone, Eq, Hash, PartialEq, Debug, Default)]
pub enum TeeType {
    PLAIN = -1,
    TPM = 0,
    #[default]
    TDX = 1,
    SEV = 2,
    CCA = 3,
}

impl From<TeeType> for String {
    fn from(t: TeeType) -> String {
        match t {
            TeeType::PLAIN => "PLAIN".to_string(),
            TeeType::TPM => "TPM".to_string(),
            TeeType::TDX => "TDX".to_string(),
            TeeType::SEV => "SEV".to_string(),
            TeeType::CCA => "CCA".to_string(),
        }
    }
}

// public known device node path
pub const TEE_TPM_PATH: &str = "/dev/tpm0";
pub const TEE_TDX_1_0_PATH: &str = "/dev/tdx-guest";
pub const TEE_TDX_1_5_PATH: &str = "/dev/tdx_guest";
pub const TEE_SEV_PATH: &str = "/dev/sev-guest";
pub const TEE_CCA_PATH: &str = "";
pub const TSM_PREFIX: &str = "/sys/kernel/config/tsm/report";

// holds the TEE type info
#[derive(Clone)]
pub struct CcType {
    pub tee_type: TeeType,
}
