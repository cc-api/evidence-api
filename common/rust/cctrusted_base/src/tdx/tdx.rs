use anyhow::*;
use log::info;
use std::result::Result::Ok;

use crate::cc_type::*;
use crate::tee::*;
use crate::tcg::{TcgAlgorithmRegistry, TcgDigest};
use crate::tdx::common::*;
use crate::tdx::rtmr::TdxRTMR;
use std::path::Path;

/*
    Tdx is an abstraction of TDX running environment, it contains:
        cc_type: should always be CcType built with TeeType::TDX
        version: TdxVersion::TDX_1_0 or TdxVersion::TDX_1_5
        device_node: /dev/tdx-guest or /dev/tdx_guest
        algo_id: should be TPM_ALG_SHA384
        cc_report_raw: the raw tdx quote in byte array
        td_report_raw: the raw td report in byte array
        rtrms: array of TdxRTMR struct
*/
pub struct Tdx {
    pub cc_type: CcType,
    pub version: TdxVersion,
    pub device_node: DeviceNode,
    pub algo_id: u8,
    pub cc_report_raw: Vec<u8>,
    pub td_report_raw: Vec<u8>,
    pub rtrms: Vec<TdxRTMR>,
}

// implement the structure method and associated function
impl Tdx {
    // associated function: to build a Tdx sturcture instance
    pub fn new() -> Tdx {
        let cc_type = CcType {
            tee_type: TeeType::TDX,
            tee_type_str: TEE_NAME_MAP.get(&TeeType::TDX).unwrap().to_owned(),
        };

        let version = Self::get_tdx_version();
        let device_node = DeviceNode {
            device_path: TDX_DEVICE_NODE_MAP.get(&version).unwrap().to_owned(),
        };
        let algo_id = crate::tcg::TPM_ALG_SHA384;

        Tdx {
            cc_type,
            version,
            device_node,
            algo_id,
            cc_report_raw: Vec::new(),
            td_report_raw: Vec::new(),
            rtrms: Vec::new(),
        }
    }

    // associated function to detect the TDX version
    fn get_tdx_version() -> TdxVersion {
        if Path::new(TEE_TDX_1_0_PATH).exists() {
            TdxVersion::TDX_1_0
        } else if Path::new(TEE_TDX_1_5_PATH).exists() {
            TdxVersion::TDX_1_5
        } else {
            TdxVersion::TDX_1_0
        }
    }
}

// Tdx implements the interfaces defined in TEE trait
impl TEE for Tdx {
    // retrieve TDX quote
    fn process_cc_report(&mut self, nonce: String, data: String) -> Result<Vec<u8>, anyhow::Error> {
        let report_data = match self.generate_tdx_report_data(nonce, Some(data)) {
            Ok(r) => r,
            Err(e) => {
                return Err(anyhow!(
                    "[get_cc_report] error generating TDX report data: {:?}",
                    e
                ))
            }
        };

        match self.get_tdx_quote(report_data) {
            Ok(q) => Ok(q),
            Err(e) => return Err(anyhow!("[get_cc_report] error getting TDX quote: {:?}", e)),
        }
    }

    // retrieve TDX RTMR
    fn process_cc_measurement(&self, _index: u8, _algo_id: u8) -> TcgDigest {
        todo!()
    }

    // retrieve TDX CCEL and IMA eventlog
    fn process_cc_eventlog(&self) -> () {
        todo!()
    }

    fn get_cc_type(&self) -> CcType {
        return self.cc_type.clone();
    }

    fn dump(&self) {
        info!("======================================");
        info!("TEE type = {}", self.cc_type.tee_type_str);
        info!(
            "TEE version = {}",
            TDX_VERSION_MAP.get(&self.version).unwrap().to_owned()
        );
        info!("======================================");
    }
}

impl TcgAlgorithmRegistry for Tdx {
    fn get_algorithm_id(&self) -> u8 {
        self.algo_id
    }
}

impl BuildTee for Tdx {}
