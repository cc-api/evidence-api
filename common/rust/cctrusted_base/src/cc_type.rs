use anyhow::*;
use std::collections::HashMap;
use std::path::Path;
use std::result::Result;

use crate::tee::TEE;
use crate::tcg::TcgAlgorithmRegistry;
use crate::tdx::tdx::Tdx;

// supported TEE types
#[derive(Clone, Eq, Hash, PartialEq)]
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

// used for return of Boxed trait object in build_tee()
pub trait BuildTee: TEE + TcgAlgorithmRegistry {}

impl CcType {
    // a function to detect the TEE type
    pub fn new() -> CcType {
        let mut tee_type = TeeType::PLAIN;
        if Path::new(TEE_TPM_PATH).exists() {
            tee_type = TeeType::TPM;
        } else if Path::new(TEE_TDX_1_0_PATH).exists() || Path::new(TEE_TDX_1_5_PATH).exists() {
            tee_type = TeeType::TDX;
        } else if Path::new(TEE_SEV_PATH).exists() {
            tee_type = TeeType::SEV;
        } else {
            // TODO add support for CCA and etc.
        }

        CcType {
            tee_type: tee_type.clone(),
            tee_type_str: TEE_NAME_MAP.get(&tee_type).unwrap().to_owned(),
        }
    }

    pub fn build_tee() -> Result<Box<dyn BuildTee>, anyhow::Error> {
        // instance a tee according to detected TEE type
        match CcType::new().tee_type {
            TeeType::TDX => Ok(Box::new(Tdx::new())),
            TeeType::SEV => todo!(),
            TeeType::CCA => todo!(),
            TeeType::TPM => todo!(),
            TeeType::PLAIN => return Err(anyhow!("[build_tee] Error: not in any TEE!")),
        }
    }
}
