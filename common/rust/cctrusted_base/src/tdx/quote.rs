#![allow(non_camel_case_types)]
use anyhow::*;
use nix::*;
use std::convert::TryInto;
use std::fs::File;
use std::mem;
use std::os::unix::io::AsRawFd;
use std::ptr;
use std::result::Result;
use std::result::Result::Ok;

use super::common::*;
use super::tdx::*;

#[repr(C)]
struct qgs_msg_header {
    major_version: u16, // TDX major version
    minor_version: u16, // TDX minor version
    msg_type: u32,      // GET_QUOTE_REQ or GET_QUOTE_RESP
    size: u32,          // size of the whole message, include this header, in byte
    error_code: u32,    // used in response only
}

#[repr(C)]
struct qgs_msg_get_quote_req {
    header: qgs_msg_header,                        // header.type = GET_QUOTE_REQ
    report_size: u32,                              // cannot be 0
    id_list_size: u32,                             // length of id_list, in byte, can be 0
    report_id_list: [u8; TDX_REPORT_LEN as usize], // report followed by id list
}

#[repr(C)]
struct tdx_quote_hdr {
    version: u64,                       // Quote version, filled by TD
    status: u64,                        // Status code of Quote request, filled by VMM
    in_len: u32,                        // Length of TDREPORT, filled by TD
    out_len: u32,                       // Length of Quote, filled by VMM
    data_len_be_bytes: [u8; 4],         // big-endian 4 bytes indicate the size of data following
    data: [u8; TDX_QUOTE_LEN as usize], // Actual Quote data or TDREPORT on input
}

#[repr(C)]
#[allow(private_in_public)]
struct tdx_quote_req {
    buf: u64, // Pass user data that includes TDREPORT as input. Upon successful completion of IOCTL, output is copied back to the same buffer
    len: u64, // Length of the Quote buffer
}

#[repr(C)]
struct qgs_msg_get_quote_resp {
    header: qgs_msg_header,        // header.type = GET_QUOTE_RESP
    selected_id_size: u32,         // can be 0 in case only one id is sent in request
    quote_size: u32,               // length of quote_data, in byte
    id_quote: [u8; TDX_QUOTE_LEN], // selected id followed by quote
}

impl Tdx {
    pub fn get_tdx_quote(&self, report_data: String) -> Result<Vec<u8>, anyhow::Error> {
        //retrieve TDX report
        let report_data_vec = match self.get_td_report(report_data) {
            Err(e) => return Err(anyhow!("[get_tdx_quote] Fail to get TDX report: {:?}", e)),
            Ok(report) => report,
        };
        let report_data_array: [u8; TDX_REPORT_LEN as usize] = match report_data_vec.try_into() {
            Ok(r) => r,
            Err(e) => return Err(anyhow!("[get_tdx_quote] Wrong TDX report format: {:?}", e)),
        };

        //build QGS request message
        let qgs_msg = self.generate_qgs_quote_msg(report_data_array);

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

        //build quote generation request header
        let mut quote_header = tdx_quote_hdr {
            version: 1,
            status: 0,
            in_len: (mem::size_of_val(&qgs_msg) + 4) as u32,
            out_len: 0,
            data_len_be_bytes: (1048 as u32).to_be_bytes(),
            data: [0; TDX_QUOTE_LEN as usize],
        };

        let qgs_msg_bytes = unsafe {
            let ptr = &qgs_msg as *const qgs_msg_get_quote_req as *const u8;
            std::slice::from_raw_parts(ptr, mem::size_of::<qgs_msg_get_quote_req>())
        };
        quote_header.data[0..(16 + 8 + TDX_REPORT_LEN) as usize]
            .copy_from_slice(&qgs_msg_bytes[0..((16 + 8 + TDX_REPORT_LEN) as usize)]);

        let request = tdx_quote_req {
            buf: ptr::addr_of!(quote_header) as u64,
            len: TDX_QUOTE_LEN as u64,
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
                    get_quote_1_0_ioctl(device_node.as_raw_fd(), ptr::addr_of!(request) as *mut u64)
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
                        ptr::addr_of!(request) as *mut tdx_quote_req,
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
            unsafe { std::mem::transmute::<[u8; 4], u32>(quote_header.data_len_be_bytes) }.to_be();

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

    fn generate_qgs_quote_msg(
        &self,
        report: [u8; TDX_REPORT_LEN as usize],
    ) -> qgs_msg_get_quote_req {
        //build quote service message header to be used by QGS
        let qgs_header = qgs_msg_header {
            major_version: 1,
            minor_version: 0,
            msg_type: 0,
            size: 16 + 8 + TDX_REPORT_LEN, // header + report_size and id_list_size + TDX_REPORT_LEN
            error_code: 0,
        };

        //build quote service message body to be used by QGS
        let mut qgs_request = qgs_msg_get_quote_req {
            header: qgs_header,
            report_size: TDX_REPORT_LEN,
            id_list_size: 0,
            report_id_list: [0; TDX_REPORT_LEN as usize],
        };

        qgs_request.report_id_list.copy_from_slice(&report[0..]);

        qgs_request
    }
}

pub struct TdxQuote {
    pub dummy_var1: u8,
    pub dummy_var2: u8,
}

impl TdxQuote {
    pub fn parse_tdx_quote(_quote: Vec<u8>) -> Result<TdxQuote, anyhow::Error> {
        Ok(TdxQuote {
            dummy_var1: 1,
            dummy_var2: 2,
        })
    }
}
