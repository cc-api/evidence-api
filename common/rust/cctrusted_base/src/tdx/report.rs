#![allow(non_camel_case_types)]
use crate::tdx::common::*;
use anyhow::*;
use core::result::Result;
use core::result::Result::Ok;
use sha2::{Digest, Sha512};

#[repr(C)]
pub struct tdx_1_0_report_req {
    pub subtype: u8,     // Subtype of TDREPORT: fixed as 0 by TDX Module specification
    pub reportdata: u64, // User-defined REPORTDATA to be included into TDREPORT
    pub rpd_len: u32, // Length of the REPORTDATA: fixed as 64 bytes by the TDX Module specification
    pub tdreport: u64, // TDREPORT output from TDCALL[TDG.MR.REPORT]
    pub tdr_len: u32, // Length of the TDREPORT: fixed as 1024 bytes by the TDX Module specification
}

#[repr(C)]
pub struct tdx_1_5_report_req {
    pub reportdata: [u8; REPORT_DATA_LEN as usize], // User buffer with REPORTDATA to be included into TDREPORT
    pub tdreport: [u8; TDX_REPORT_LEN as usize], // User buffer to store TDREPORT output from TDCALL[TDG.MR.REPORT]
}

impl Tdx {
    /***
        generate tdx report data with nonce and data

        Args:
            nonce (String): against replay attacks
            data (String): user data

        Returns:
            The tdreport byte array
    */
    pub fn generate_tdx_report_data(
        nonce: String,
        data: Option<String>,
    ) -> Result<String, anyhow::Error> {
        let nonce_decoded = match base64::decode(nonce) {
            Ok(v) => v,
            Err(e) => {
                return Err(anyhow!(
                    "[generate_tdx_report_data] nonce is not base64 encoded: {:?}",
                    e
                ))
            }
        };
        let mut hasher = Sha512::new();
        hasher.update(nonce_decoded);
        let _ret = match data {
            Some(_encoded_data) => {
                if _encoded_data.is_empty() {
                    hasher.update("")
                } else {
                    let decoded_data = match base64::decode(_encoded_data) {
                        Ok(v) => v,
                        Err(e) => {
                            return Err(anyhow!(
                                "[generate_tdx_report_data] user data is not base64 encoded: {:?}",
                                e
                            ))
                        }
                    };
                    hasher.update(decoded_data)
                }
            }
            None => hasher.update(""),
        };
        let hash_array: [u8; 64] = hasher
            .finalize()
            .as_slice()
            .try_into()
            .expect("[generate_tdx_report_data] Wrong length of report data");
        Ok(base64::encode(hash_array))
    }
}
