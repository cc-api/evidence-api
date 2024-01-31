#![allow(non_camel_case_types)]

use crate::cvm::*;
use anyhow::*;
use cctrusted_base::api_data::ReplayResult;
use cctrusted_base::cc_type::*;
use cctrusted_base::eventlog::EventLogs;
use cctrusted_base::tcg::EventLogEntry;
use cctrusted_base::tcg::*;
use cctrusted_base::tdx::common::*;
use cctrusted_base::tdx::quote::*;
use cctrusted_base::tdx::report::*;
use cctrusted_base::tdx::rtmr::TdxRTMR;
use core::convert::TryInto;
use core::mem;
use core::ptr;
use core::result::Result;
use core::result::Result::Ok;
use log::info;
use nix::*;
use std::fs::read_to_string;
use std::fs::File;
use std::io::BufReader;
use std::io::Read;
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
    pub algo_id: u16,
}

// implement the structure method and associated function
impl Default for TdxVM {
    fn default() -> Self {
        Self::new()
    }
}

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
    fn get_td_report(
        &self,
        nonce: Option<String>,
        data: Option<String>,
    ) -> Result<Vec<u8>, anyhow::Error> {
        let report_data = match Tdx::generate_tdx_report_data(nonce, data) {
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
                if let Err(e) = unsafe {
                    get_report_1_0_ioctl(
                        device_node.as_raw_fd(),
                        ptr::addr_of!(request) as *mut u64,
                    )
                } {
                    return Err(anyhow!("[get_td_report] Fail to get TDX report: {:?}", e));
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
                if let Err(e) = unsafe {
                    get_report_1_5_ioctl(
                        device_node.as_raw_fd(),
                        ptr::addr_of!(request) as *mut tdx_1_5_report_req,
                    )
                } {
                    return Err(anyhow!("[get_td_report] Fail to get TDX report: {:?}", e));
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
    fn process_cc_report(
        &mut self,
        nonce: Option<String>,
        data: Option<String>,
    ) -> Result<Vec<u8>, anyhow::Error> {
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

    // CVM trait function: get tdx rtmr max index
    fn get_max_index(&self) -> u8 {
        TdxRTMR::max_index()
    }

    // CVM trait function: retrieve TDX RTMR
    fn process_cc_measurement(&self, index: u8, algo_id: u16) -> Result<TcgDigest, anyhow::Error> {
        match TdxRTMR::is_valid_index(index) {
            Ok(_) => (),
            Err(e) => return Err(anyhow!("[process_cc_measurement] {:?}", e)),
        };

        match TdxRTMR::is_valid_algo(algo_id) {
            Ok(_) => (),
            Err(e) => return Err(anyhow!("[process_cc_measurement] {:?}", e)),
        };

        let tdreport_raw = match self.get_td_report(None, None) {
            Ok(r) => r,
            Err(e) => {
                return Err(anyhow!(
                    "[process_cc_measurement] error getting TD report: {:?}",
                    e
                ))
            }
        };

        let tdreport = match Tdx::parse_td_report(&tdreport_raw, self.version.clone()) {
            Ok(r) => r,
            Err(e) => {
                return Err(anyhow!(
                    "[process_cc_measurement] error parsing TD report: {:?}",
                    e
                ))
            }
        };

        match TdxRTMR::new(index, algo_id, tdreport.td_info.rtmrs[index as usize]) {
            Ok(rtmr) => Ok(rtmr.get_tcg_digest(algo_id)),
            Err(e) => Err(anyhow!("error creating TdxRTMR {:?}", e)),
        }
    }

    // CVM trait function: retrieve TDX CCEL and IMA eventlog
    fn process_cc_eventlog(
        &self,
        start: Option<u32>,
        count: Option<u32>,
    ) -> Result<Vec<EventLogEntry>, anyhow::Error> {
        let (acpi_table_file, acpi_table_data_file, ima_data_file);

        if !Path::new(ACPI_TABLE_FILE_VM).exists() {
            if !Path::new(ACPI_TABLE_FILE_CONTAINER).exists() {
                return Err(anyhow!(
                    "[process_cc_eventlog] Failed to find TDX CCEL table file at {:?} or {:?}",
                    ACPI_TABLE_FILE_VM,
                    ACPI_TABLE_FILE_CONTAINER
                ));
            } else {
                acpi_table_file = ACPI_TABLE_FILE_CONTAINER.to_string();
            }
        } else {
            acpi_table_file = ACPI_TABLE_FILE_VM.to_string();
        }

        if !Path::new(ACPI_TABLE_DATA_FILE_VM).exists() {
            if !Path::new(ACPI_TABLE_DATA_FILE_CONTAINER).exists() {
                return Err(anyhow!(
                    "[process_cc_eventlog] Failed to find TDX CCEL table data at {:?} or {:?}",
                    ACPI_TABLE_DATA_FILE_VM,
                    ACPI_TABLE_DATA_FILE_CONTAINER
                ));
            } else {
                acpi_table_data_file = ACPI_TABLE_DATA_FILE_CONTAINER.to_string();
            }
        } else {
            acpi_table_data_file = ACPI_TABLE_DATA_FILE_VM.to_string();
        }

        // read ACPI data
        let ccel_file = File::open(acpi_table_file)?;
        let mut ccel_reader = BufReader::new(ccel_file);
        let mut ccel = Vec::new();
        ccel_reader.read_to_end(&mut ccel)?;
        let ccel_char_vec = ['C', 'C', 'E', 'L'];
        let ccel_u8_vec: Vec<u8> = ccel_char_vec.iter().map(|c| *c as u8).collect::<Vec<_>>();
        if ccel.is_empty() || (ccel[0..4].to_vec() != ccel_u8_vec) {
            return Err(anyhow!("[process_cc_eventlog] Invalid CCEL table"));
        }

        let boot_time_data_file = File::open(acpi_table_data_file)?;
        let mut boot_time_data_reader = BufReader::new(boot_time_data_file);
        let mut boot_time_data = Vec::new();
        boot_time_data_reader.read_to_end(&mut boot_time_data)?;

        // read IMA data
        /*
          First check if the identifier 'ima_hash=sha384' exists on kernel cmdline
          If yes, suppose IMA over RTMR enabled in kernel (IMA over RTMR patch included in
          https://github.com/intel/tdx-tools/blob/tdx-1.5/build/common/patches-tdx-kernel-MVP-KERNEL-6.2.16-v5.0.tar.gz)
          If not, suppose IMA over RTMR not enabled in kernel
        */

        if !Path::new(IMA_DATA_FILE_VM).exists() {
            if !Path::new(IMA_DATA_FILE_CONTAINER).exists() {
                return Err(anyhow!(
                    "[process_cc_eventlog] Failed to find TDX CCEL table data at {:?} or {:?}",
                    IMA_DATA_FILE_VM,
                    IMA_DATA_FILE_CONTAINER
                ));
            } else {
                ima_data_file = IMA_DATA_FILE_CONTAINER.to_string();
            }
        } else {
            ima_data_file = IMA_DATA_FILE_VM.to_string();
        }

        let mut run_time_data = Vec::new();

        let cmdline_file = File::open("/proc/cmdline")?;
        let mut cmdline_reader = BufReader::new(cmdline_file);
        let mut cmdline_string = String::new();
        let _ = cmdline_reader.read_to_string(&mut cmdline_string);
        if cmdline_string.contains("ima_hash=sha384") {
            run_time_data = read_to_string(ima_data_file)
                .unwrap()
                .lines()
                .map(String::from)
                .collect();
        }

        let mut eventlogs = EventLogs::new(boot_time_data, run_time_data, TCG_PCCLIENT_FORMAT);
        eventlogs.select(start, count)
    }

    fn replay_eventlog(
        &self,
        eventlogs: Vec<EventLogEntry>,
    ) -> Result<Vec<ReplayResult>, anyhow::Error> {
        EventLogs::replay(eventlogs)
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
    fn get_algorithm_id(&self) -> u16 {
        self.algo_id
    }

    fn get_algorithm_id_str(&self) -> String {
        ALGO_NAME_MAP.get(&self.algo_id).unwrap().to_owned()
    }
}

impl BuildCVM for TdxVM {}
