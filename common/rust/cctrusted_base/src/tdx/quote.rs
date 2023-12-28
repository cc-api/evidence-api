#![allow(non_camel_case_types)]
use core::result::Result;
use core::result::Result::Ok;

use crate::tdx::common::*;

#[repr(C)]
pub struct qgs_msg_header {
    pub major_version: u16, // TDX major version
    pub minor_version: u16, // TDX minor version
    pub msg_type: u32,      // GET_QUOTE_REQ or GET_QUOTE_RESP
    pub size: u32,          // size of the whole message, include this header, in byte
    pub error_code: u32,    // used in response only
}

#[repr(C)]
pub struct qgs_msg_get_quote_req {
    pub header: qgs_msg_header, // header.type = GET_QUOTE_REQ
    pub report_size: u32,       // cannot be 0
    pub id_list_size: u32,      // length of id_list, in byte, can be 0
    pub report_id_list: [u8; TDX_REPORT_LEN as usize], // report followed by id list
}

#[repr(C)]
pub struct tdx_quote_hdr {
    pub version: u64,                       // Quote version, filled by TD
    pub status: u64,                        // Status code of Quote request, filled by VMM
    pub in_len: u32,                        // Length of TDREPORT, filled by TD
    pub out_len: u32,                       // Length of Quote, filled by VMM
    pub data_len_be_bytes: [u8; 4], // big-endian 4 bytes indicate the size of data following
    pub data: [u8; TDX_QUOTE_LEN as usize], // Actual Quote data or TDREPORT on input
}

#[repr(C)]
pub struct tdx_quote_req {
    pub buf: u64, // Pass user data that includes TDREPORT as input. Upon successful completion of IOCTL, output is copied back to the same buffer
    pub len: u64, // Length of the Quote buffer
}

#[repr(C)]
pub struct qgs_msg_get_quote_resp {
    pub header: qgs_msg_header,        // header.type = GET_QUOTE_RESP
    pub selected_id_size: u32,         // can be 0 in case only one id is sent in request
    pub quote_size: u32,               // length of quote_data, in byte
    pub id_quote: [u8; TDX_QUOTE_LEN], // selected id followed by quote
}

impl Tdx {
    /***
        generate qgs message for TDX quote generation

        Args:
            report (Vec<u8>): tdreport

        Returns:
            qgs_msg_get_quote_req struct instance
    */
    pub fn generate_qgs_quote_msg(report: [u8; TDX_REPORT_LEN as usize]) -> qgs_msg_get_quote_req {
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

#[derive(Clone)]
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
