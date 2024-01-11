#![allow(non_camel_case_types)]

use crate::cvm::*;
use anyhow::*;
use cctrusted_base::cc_type::*;
use cctrusted_base::tcg::{TcgAlgorithmRegistry, TcgDigest};
use cctrusted_base::tdx::common::*;
use cctrusted_base::tdx::quote::*;
use cctrusted_base::tdx::report::*;
use core::convert::TryInto;
use core::mem;
use core::ptr;
use core::result::Result;
use core::result::Result::Ok;
use log::info;
use nix::*;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::Path;

// TDX ioctl operation code to be used for get TDX quote and TD Report
pub enum TdxOperation {
    TDX_GET_TD_REPORT = 1,
    TDX_1_0_GET_QUOTE = 2,
    TDX_1_5_GET_QUOTE = 4,
}

/*
    TdxVM is an abstraction of TDX running environment, it contains:
        cc_type: should always be CcType built with TeeType::TDX
        version: TdxVersion::TDX_1_0 or TdxVersion::TDX_1_5
        device_node: /dev/tdx-guest or /dev/tdx_guest
        algo_id: should be TPM_ALG_SHA384
*/
pub struct TdxVM {
    pub cc_type: CcType,
    pub version: TdxVersion,
    pub device_node: DeviceNode,
    pub algo_id: u8,
}

// implement the structure method and associated function
impl TdxVM {
    // TdxVM struct associated function: to build a TdxVM sturcture instance
    pub fn new() -> TdxVM {
        let cc_type = CcType {
            tee_type: TeeType::TDX,
            tee_type_str: TEE_NAME_MAP.get(&TeeType::TDX).unwrap().to_owned(),
        };

        let version = Self::get_tdx_version();
        let device_node = DeviceNode {
            device_path: TDX_DEVICE_NODE_MAP.get(&version).unwrap().to_owned(),
        };
        let algo_id = cctrusted_base::tcg::TPM_ALG_SHA384;

        TdxVM {
            cc_type,
            version,
            device_node,
            algo_id,
        }
    }

    // TdxVM struct method: get tdreport
    pub fn get_td_report(&self, nonce: String, data: String) -> Result<Vec<u8>, anyhow::Error> {
        let report_data = match Tdx::generate_tdx_report_data(nonce, Some(data)) {
            Ok(r) => r,
            Err(e) => {
                return Err(anyhow!(
                    "[get_td_report] error generating TDX report data: {:?}",
                    e
                ))
            }
        };

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
            TdxVersion::TDX_1_0 => {
                let report_data_bytes = match base64::decode(report_data) {
                    Ok(v) => v,
                    Err(e) => return Err(anyhow!("report data is not base64 encoded: {:?}", e)),
                };

                //prepare get TDX report request data
                let mut report_data_array: [u8; REPORT_DATA_LEN as usize] =
                    [0; REPORT_DATA_LEN as usize];
                report_data_array.copy_from_slice(&report_data_bytes[0..]);
                let td_report: [u8; TDX_REPORT_LEN as usize] = [0; TDX_REPORT_LEN as usize];

                //build the request
                let request = tdx_1_0_report_req {
                    subtype: 0_u8,
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
                    get_report_1_0_ioctl(
                        device_node.as_raw_fd(),
                        ptr::addr_of!(request) as *mut u64,
                    )
                } {
                    Err(e) => {
                        return Err(anyhow!("[get_td_report] Fail to get TDX report: {:?}", e))
                    }
                    Ok(_) => (),
                };

                Ok(td_report.to_vec())
            }
            TdxVersion::TDX_1_5 => {
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
                        return Err(anyhow!("[get_td_report] Fail to get TDX report: {:?}", e))
                    }
                    Ok(_) => (),
                };

                Ok(request.tdreport.to_vec())
            }
        }
    }

    // TdxVM struct associated function: detect the TDX version
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

// TdxVM implements the interfaces defined in CVM trait
impl CVM for TdxVM {
    // CVM trait function: get tdx quote
    fn process_cc_report(&mut self, nonce: String, data: String) -> Result<Vec<u8>, anyhow::Error> {
        let tdreport = match self.get_td_report(nonce, data) {
            Ok(r) => r,
            Err(e) => {
                return Err(anyhow!(
                    "[process_cc_report] error getting TD report: {:?}",
                    e
                ))
            }
        };

        let report_data_array: [u8; TDX_REPORT_LEN as usize] = match tdreport.try_into() {
            Ok(r) => r,
            Err(e) => return Err(anyhow!("[get_tdx_quote] Wrong TDX report format: {:?}", e)),
        };

        //build QGS request message
        let qgs_msg = Tdx::generate_qgs_quote_msg(report_data_array);

        //build quote generation request header
        let mut quote_header = tdx_quote_hdr {
            version: 1,
            status: 0,
            in_len: (mem::size_of_val(&qgs_msg) + 4) as u32,
            out_len: 0,
            data_len_be_bytes: (1048_u32).to_be_bytes(),
            data: [0; TDX_QUOTE_LEN],
        };

        let qgs_msg_bytes = unsafe {
            let ptr = &qgs_msg as *const qgs_msg_get_quote_req as *const u8;
            core::slice::from_raw_parts(ptr, mem::size_of::<qgs_msg_get_quote_req>())
        };
        quote_header.data[0..(16 + 8 + TDX_REPORT_LEN) as usize]
            .copy_from_slice(&qgs_msg_bytes[0..((16 + 8 + TDX_REPORT_LEN) as usize)]);

        let tdx_quote_request = tdx_quote_req {
            buf: ptr::addr_of!(quote_header) as u64,
            len: TDX_QUOTE_LEN as u64,
        };

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

        //build the operator code and apply the ioctl command
        match self.version {
            TdxVersion::TDX_1_0 => {
                ioctl_read!(
                    get_quote_1_0_ioctl,
                    b'T',
                    TdxOperation::TDX_1_0_GET_QUOTE,
                    u64
                );
                match unsafe {
                    get_quote_1_0_ioctl(
                        device_node.as_raw_fd(),
                        ptr::addr_of!(tdx_quote_request) as *mut u64,
                    )
                } {
                    Err(e) => {
                        return Err(anyhow!("[get_tdx_quote] Fail to get TDX quote: {:?}", e))
                    }
                    Ok(_r) => _r,
                };
            }
            TdxVersion::TDX_1_5 => {
                ioctl_read!(
                    get_quote_1_5_ioctl,
                    b'T',
                    TdxOperation::TDX_1_5_GET_QUOTE,
                    tdx_quote_req
                );
                match unsafe {
                    get_quote_1_5_ioctl(
                        device_node.as_raw_fd(),
                        ptr::addr_of!(tdx_quote_request) as *mut tdx_quote_req,
                    )
                } {
                    Err(e) => {
                        return Err(anyhow!("[get_tdx_quote] Fail to get TDX quote: {:?}", e))
                    }
                    Ok(_r) => _r,
                };
            }
        };

        //inspect the response and retrive quote data
        let out_len = quote_header.out_len;
        let qgs_msg_resp_size =
            unsafe { core::mem::transmute::<[u8; 4], u32>(quote_header.data_len_be_bytes) }.to_be();

        let qgs_msg_resp = unsafe {
            let raw_ptr = ptr::addr_of!(quote_header.data) as *mut qgs_msg_get_quote_resp;
            raw_ptr.as_mut().unwrap() as &mut qgs_msg_get_quote_resp
        };

        if out_len - qgs_msg_resp_size != 4 {
            return Err(anyhow!(
                "[get_tdx_quote] Fail to get TDX quote: wrong TDX quote size!"
            ));
        }

        if qgs_msg_resp.header.major_version != 1
            || qgs_msg_resp.header.minor_version != 0
            || qgs_msg_resp.header.msg_type != 1
            || qgs_msg_resp.header.error_code != 0
        {
            return Err(anyhow!(
                "[get_tdx_quote] Fail to get TDX quote: QGS response error!"
            ));
        }

        Ok(qgs_msg_resp.id_quote[0..(qgs_msg_resp.quote_size as usize)].to_vec())
    }

    // CVM trait function: retrieve TDX RTMR
    fn process_cc_measurement(&self, _index: u8, _algo_id: u8) -> TcgDigest {
        todo!()
    }

    // CVM trait function: retrieve TDX CCEL and IMA eventlog
    fn process_cc_eventlog(&self) {
        todo!()
    }

    // CVM trait function: retrive CVM type
    fn get_cc_type(&self) -> CcType {
        self.cc_type.clone()
    }

    // CVM trait function: dump CVM basic information
    fn dump(&self) {
        info!("======================================");
        info!("CVM type = {}", self.cc_type.tee_type_str);
        info!(
            "CVM version = {}",
            TDX_VERSION_MAP.get(&self.version).unwrap().to_owned()
        );
        info!("======================================");
    }
}

impl TcgAlgorithmRegistry for TdxVM {
    // TcgAlgorithmRegistry trait function: return CVM default algorithm ID
    fn get_algorithm_id(&self) -> u8 {
        self.algo_id
    }
}

impl BuildCVM for TdxVM {}