#![allow(non_camel_case_types)]
use anyhow::*;
use nix::*;
use sha2::{Digest, Sha512};
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::ptr;
use std::result::Result;
use std::result::Result::Ok;

use super::common::*;
use super::tdx::Tdx;

#[repr(C)]
#[allow(private_in_public)]
struct tdx_1_0_report_req {
    subtype: u8,     // Subtype of TDREPORT: fixed as 0 by TDX Module specification
    reportdata: u64, // User-defined REPORTDATA to be included into TDREPORT
    rpd_len: u32,    // Length of the REPORTDATA: fixed as 64 bytes by the TDX Module specification
    tdreport: u64,   // TDREPORT output from TDCALL[TDG.MR.REPORT]
    tdr_len: u32,    // Length of the TDREPORT: fixed as 1024 bytes by the TDX Module specification
}

#[repr(C)]
#[allow(private_in_public)]
struct tdx_1_5_report_req {
    reportdata: [u8; REPORT_DATA_LEN as usize], // User buffer with REPORTDATA to be included into TDREPORT
    tdreport: [u8; TDX_REPORT_LEN as usize], // User buffer to store TDREPORT output from TDCALL[TDG.MR.REPORT]
}

impl Tdx {
    pub fn generate_tdx_report_data(
        &self,
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

    pub fn get_td_report(&self, report_data: String) -> Result<Vec<u8>, anyhow::Error> {
        let device_node = match File::options()
            .read(true)
            .write(true)
            .open(self.device_node.device_path.clone())
        {
            Err(e) => {
                return Err(anyhow!(
                    "[get_td_report] Fail to open {}: {:?}",
                    self.device_node.device_path,
                    e
                ))
            }
            Ok(fd) => fd,
        };

        match self.version {
            TdxVersion::TDX_1_0 => match self.get_tdx_1_0_report(device_node, report_data) {
                Err(e) => return Err(anyhow!("[get_td_report] Fail to get TDX report: {:?}", e)),
                Ok(report) => Ok(report),
            },
            TdxVersion::TDX_1_5 => match self.get_tdx_1_5_report(device_node, report_data) {
                Err(e) => return Err(anyhow!("[get_td_report] Fail to get TDX report: {:?}", e)),
                Ok(report) => Ok(report),
            },
        }
    }

    fn get_tdx_1_0_report(
        &self,
        device_node: File,
        report_data: String,
    ) -> Result<Vec<u8>, anyhow::Error> {
        let report_data_bytes = match base64::decode(report_data) {
            Ok(v) => v,
            Err(e) => return Err(anyhow!("report data is not base64 encoded: {:?}", e)),
        };

        //prepare get TDX report request data
        let mut report_data_array: [u8; REPORT_DATA_LEN as usize] = [0; REPORT_DATA_LEN as usize];
        report_data_array.copy_from_slice(&report_data_bytes[0..]);
        let td_report: [u8; TDX_REPORT_LEN as usize] = [0; TDX_REPORT_LEN as usize];

        //build the request
        let request = tdx_1_0_report_req {
            subtype: 0 as u8,
            reportdata: ptr::addr_of!(report_data_array) as u64,
            rpd_len: REPORT_DATA_LEN,
            tdreport: ptr::addr_of!(td_report) as u64,
            tdr_len: TDX_REPORT_LEN,
        };

        //build the operator code
        ioctl_readwrite!(
            get_report_1_0_ioctl,
            b'T',
            TdxOperation::TDX_GET_TD_REPORT,
            u64
        );

        //apply the ioctl command
        match unsafe {
            get_report_1_0_ioctl(device_node.as_raw_fd(), ptr::addr_of!(request) as *mut u64)
        } {
            Err(e) => {
                return Err(anyhow!(
                    "[get_tdx_1_0_report] Fail to get TDX report: {:?}",
                    e
                ))
            }
            Ok(_) => (),
        };

        Ok(td_report.to_vec())
    }

    fn get_tdx_1_5_report(
        &self,
        device_node: File,
        report_data: String,
    ) -> Result<Vec<u8>, anyhow::Error> {
        let report_data_bytes = match base64::decode(report_data) {
            Ok(v) => v,
            Err(e) => return Err(anyhow!("report data is not base64 encoded: {:?}", e)),
        };

        //prepare get TDX report request data
        let mut request = tdx_1_5_report_req {
            reportdata: [0; REPORT_DATA_LEN as usize],
            tdreport: [0; TDX_REPORT_LEN as usize],
        };
        request.reportdata.copy_from_slice(&report_data_bytes[0..]);

        //build the operator code
        ioctl_readwrite!(
            get_report_1_5_ioctl,
            b'T',
            TdxOperation::TDX_GET_TD_REPORT,
            tdx_1_5_report_req
        );

        //apply the ioctl command
        match unsafe {
            get_report_1_5_ioctl(
                device_node.as_raw_fd(),
                ptr::addr_of!(request) as *mut tdx_1_5_report_req,
            )
        } {
            Err(e) => {
                return Err(anyhow!(
                    "[get_tdx_1_5_report] Fail to get TDX report: {:?}",
                    e
                ))
            }
            Ok(_) => (),
        };

        Ok(request.tdreport.to_vec())
    }
}
