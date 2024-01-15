#![allow(non_camel_case_types)]
use crate::tdx::common::*;
use anyhow::*;
use core::mem::transmute;
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

/***
   Struct REPORTMACSTRUCT's layout:
       offset, len
       0x0,    0x8     report_type
       0x8,    0x8     reserverd1
       0x10,   0x10    cpusvn
       0x20,   0x30    tee_tcb_info_hash
       0x50,   0x30    tee_info_hash
       0x80,   0x40    report_data
       0xc0,   0x20    reserverd2
       0xe0,   0x20    mac
*/
#[repr(C)]
#[derive(Clone)]
pub struct ReportMacStruct {
    pub report_type: [u8; 8],
    pub reserverd1: [u8; 8],
    pub cpusvn: [u8; 16],
    pub tee_tcb_info_hash: [u8; 48],
    pub tee_info_hash: [u8; 48],
    pub report_data: [u8; 64],
    pub reserverd2: [u8; 32],
    pub mac: [u8; 32],
}

/***
   Struct TEE_TCB_INFO's layout:
       offset, len
       0x0,    0x08    valid
       0x8,    0x10    tee_tcb_svn
       0x18,   0x30    mrseam
       0x48,   0x30    mrsignerseam
       0x78,   0x08    attributes
       # fileds in tdx v1.0
       0x80,   0x6f    reserved
       # fileds in tdx v1.5
       0x80,   0x10    tee_tcb_svn2
       0x90,   0x5f    reserved
*/
#[repr(C)]
#[derive(Clone)]
pub struct TeeTcbInfo {
    pub valid: [u8; 8],
    pub tee_tcb_svn: [u8; 16],
    pub mrseam: [u8; 48],
    pub mrsignerseam: [u8; 48],
    pub attributes: [u8; 8],
    pub tee_tcb_svn2: Option<[u8; 16]>,
    pub reserved: Vec<u8>,
}

impl TeeTcbInfo {
    pub fn new(data: Vec<u8>, tdx_version: TdxVersion) -> TeeTcbInfo {
        let valid = data[0..8].try_into().unwrap();
        let tee_tcb_svn = data[8..24].try_into().unwrap();
        let mrseam = data[24..72].try_into().unwrap();
        let mrsignerseam = data[72..120].try_into().unwrap();
        let attributes = data[120..128].try_into().unwrap();

        if tdx_version == TdxVersion::TDX_1_0 {
            let reserved = data[128..].try_into().unwrap();
            TeeTcbInfo {
                valid,
                tee_tcb_svn,
                mrseam,
                mrsignerseam,
                attributes,
                tee_tcb_svn2: None,
                reserved,
            }
        } else {
            // TDX 1.5
            let reserved = data[144..].try_into().unwrap();
            TeeTcbInfo {
                valid,
                tee_tcb_svn,
                mrseam,
                mrsignerseam,
                attributes,
                tee_tcb_svn2: Some(data[128..144].try_into().unwrap()),
                reserved,
            }
        }
    }
}

/***
   Struct TDINFO_STRUCT's layout:
       offset, len
       0x0,    0x8     attributes
       0x8,    0x8     xfam
       0x10,   0x30    mrtd
       0x40,   0x30    mrconfigid
       0x70,   0x30    mrowner
       0xa0,   0x30    mrownerconfig
       0xd0,   0x30    rtmr_0
       0x100,  0x30    rtmr_1
       0x130,  0x30    rtmr_2
       0x160,  0x30    rtmr_3
       # fields in tdx v1.0
       0x190,  0x70    reserved
       # fields in tdx v1.5
       0x190,  0x30    servtd_hash
       0x1c0,  0x40    reserved
   ref:
       Page 40 of Intel® TDX Module v1.5 ABI Specification
       from https://www.intel.com/content/www/us/en/developer/articles/technical/
       intel-trust-domain-extensions.html
*/
#[repr(C)]
#[derive(Clone)]
pub struct TdInfo {
    pub attributes: [u8; 8],
    pub xfam: [u8; 8],
    pub mrtd: [u8; 48],
    pub mrconfigid: [u8; 48],
    pub mrowner: [u8; 48],
    pub mrownerconfig: [u8; 48],
    pub rtmrs: Vec<[u8; 48]>,
    pub servtd_hash: Option<[u8; 48]>,
    pub reserved: Vec<u8>,
}

impl TdInfo {
    pub fn new(data: Vec<u8>, tdx_version: TdxVersion) -> TdInfo {
        let attributes = data[0..8].try_into().unwrap();
        let xfam = data[8..16].try_into().unwrap();
        let mrtd = data[16..64].try_into().unwrap();
        let mrconfigid = data[64..112].try_into().unwrap();
        let mrowner = data[112..160].try_into().unwrap();
        let mrownerconfig = data[160..208].try_into().unwrap();
        let mut rtmrs = Vec::new();
        rtmrs.push(data[208..256].try_into().unwrap());
        rtmrs.push(data[256..304].try_into().unwrap());
        rtmrs.push(data[304..352].try_into().unwrap());
        rtmrs.push(data[352..400].try_into().unwrap());

        if tdx_version == TdxVersion::TDX_1_0 {
            TdInfo {
                attributes,
                xfam,
                mrtd,
                mrconfigid,
                mrowner,
                mrownerconfig,
                rtmrs,
                servtd_hash: None,
                reserved: data[400..].try_into().unwrap(),
            }
        } else {
            // TDX 1.5
            TdInfo {
                attributes,
                xfam,
                mrtd,
                mrconfigid,
                mrowner,
                mrownerconfig,
                rtmrs,
                servtd_hash: Some(data[400..448].try_into().unwrap()),
                reserved: data[448..].try_into().unwrap(),
            }
        }
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct TDReport {
    pub report_mac_struct: ReportMacStruct,
    pub tee_tcb_info: TeeTcbInfo,
    pub reserved: [u8; 17],
    pub td_info: TdInfo,
}

impl Tdx {
    /***
        generate tdx data with nonce and data

        Args:
            nonce (String): against replay attacks
            data (String): user data

        Returns:
            The tdreport byte array
    */
    pub fn generate_tdx_report_data(
        nonce: Option<String>,
        data: Option<String>,
    ) -> Result<String, anyhow::Error> {
        let mut hasher = Sha512::new();

        match nonce {
            Some(_encoded_nonce) => {
                if _encoded_nonce.is_empty() {
                    hasher.update("")
                } else {
                    let decoded_nonce = match base64::decode(_encoded_nonce) {
                        Ok(v) => v,
                        Err(e) => {
                            return Err(anyhow!(
                                "[generate_tdx_report_data] nonce is not base64 encoded: {:?}",
                                e
                            ))
                        }
                    };
                    hasher.update(decoded_nonce)
                }
            }
            None => hasher.update(""),
        };

        match data {
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
            .expect("[generate_tdx_report_data] Wrong length of data");
        Ok(base64::encode(hash_array))
    }

    pub fn parse_td_report(
        report: &Vec<u8>,
        tdx_version: TdxVersion,
    ) -> Result<TDReport, anyhow::Error> {
        let report_mac_struct = unsafe {
            transmute::<[u8; 256], ReportMacStruct>(
                report[0..256]
                    .try_into()
                    .expect("slice with incorrect length"),
            )
        };
        let tee_tcb_info = TeeTcbInfo::new(report[256..495].to_vec(), tdx_version.clone());
        let reserved = report[495..512].try_into().unwrap();
        let td_info = TdInfo::new(report[512..1024].to_vec(), tdx_version.clone());
        Ok(TDReport {
            report_mac_struct,
            tee_tcb_info,
            reserved,
            td_info,
        })
    }
}

#[cfg(test)]
mod test_generate_tdx_report_data {
    use super::*;
    use crate::tdx::common::Tdx;

    #[test]
    //generate_tdx_report allow optional nonce
    fn test_generate_tdx_report_data_no_nonce() {
        let result = Tdx::generate_tdx_report_data(None, Some("YWJjZGVmZw==".to_string()));
        assert!(result.is_ok());
    }

    #[test]
    //generate_tdx_report allow optional data
    fn tdx_get_quote_report_data_no_data() {
        let result = Tdx::generate_tdx_report_data(Some("IXUKoBO1XEFBPwopN4sY".to_string()), None);
        assert!(result.is_ok());
    }

    #[test]
    //generate_tdx_report allow empty data
    fn test_generate_tdx_report_data_data_size_0() {
        let result = Tdx::generate_tdx_report_data(
            Some("IXUKoBO1XEFBPwopN4sY".to_string()),
            Some("".to_string()),
        );
        assert!(result.is_ok());
    }

    #[test]
    //generate_tdx_report require data string is base64 encoded
    fn test_generate_tdx_report_data_data_not_base64_encoded() {
        //coming in data should always be base64 encoded
        let result = Tdx::generate_tdx_report_data(
            Some("IXUKoBO1XEFBPwopN4sY".to_string()),
            Some("XD^%*!x".to_string()),
        );
        assert!(result.is_err());
    }

    #[test]
    //generate_tdx_report require nonce string is base64 encoded
    fn test_generate_tdx_report_data_nonce_not_base64_encoded() {
        //coming in nonce should always be base64 encoded
        let result = Tdx::generate_tdx_report_data(
            Some("XD^%*!x".to_string()),
            Some("IXUKoBO1XEFBPwopN4sY".to_string()),
        );
        assert!(result.is_err());
    }

    #[test]
    //generate_tdx_report require nonce string is base64 encoded
    fn test_generate_tdx_report_data_nonce_too_short_not_base64_encoded() {
        //coming in nonce should always be base64 encoded
        let result = Tdx::generate_tdx_report_data(
            Some("123".to_string()),
            Some("IXUKoBO1XEFBPwopN4sY".to_string()),
        );
        assert!(result.is_err());
    }

    #[test]
    //generate_tdx_report require data string is base64 encoded
    fn test_generate_tdx_report_data_report_data_too_short_not_base64_encoded() {
        //coming in data should always be base64 encoded
        let result = Tdx::generate_tdx_report_data(
            Some("IXUKoBO1XEFBPwopN4sY".to_string()),
            Some("123".to_string()),
        );
        assert!(result.is_err());
    }

    #[test]
    //generate_tdx_report check result as expected
    //orginal nonce = "12345678", original data = "abcdefgh"
    fn test_generate_tdx_report_data_report_data_nonce_base64_encoded_as_expected() {
        let result = Tdx::generate_tdx_report_data(
            Some("MTIzNDU2Nzg=".to_string()),
            Some("YWJjZGVmZw==".to_string()),
        )
        .unwrap();
        let expected_hash = [
            93, 71, 28, 83, 115, 189, 166, 130, 87, 137, 126, 119, 140, 209, 163, 215, 13, 175,
            225, 101, 64, 195, 196, 202, 15, 37, 166, 241, 141, 49, 128, 157, 164, 132, 67, 50, 9,
            32, 162, 89, 243, 191, 177, 131, 4, 159, 156, 104, 11, 193, 18, 217, 92, 215, 194, 98,
            145, 191, 211, 85, 187, 118, 39, 80,
        ];
        let generated_hash = base64::decode(result).unwrap();
        assert_eq!(generated_hash, expected_hash);
    }

    #[test]
    //generate_tdx_report allow long data string
    fn test_generate_tdx_report_data_long_tdx_data() {
        let result = Tdx::generate_tdx_report_data(
            Some("IXUKoBO1XEFBPwopN4sY".to_string()),
            Some(
                "MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4MTIzNDU2Nzgx\
                MjM0NTY3ODEyMzQ1Njc4MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4MTIzNDU2NzgxMjM0NTY3ODEy\
                MzQ1Njc4MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4MTIz\
                NDU2NzgxMjM0NTY3ODEyMzQ1Njc4MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4MTIzNDU2NzgxMjM0\
                NTY3ODEyMzQ1Njc4MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4MTIzNDU2NzgxMjM0NTY3ODEyMzQ1\
                Njc4MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4MTIzNDU2\
                NzgxMjM0NTY3ODEyMzQ1Njc4MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4Cg=="
                    .to_string(),
            ),
        );
        assert!(result.is_ok());
    }

    #[test]
    //generate_tdx_report allow long nonce string
    fn test_generate_tdx_report_data_long_nonce() {
        let result = Tdx::generate_tdx_report_data(
            Some(
                "MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4MTIzNDU2Nzgx\
            MjM0NTY3ODEyMzQ1Njc4MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4MTIzNDU2NzgxMjM0NTY3ODEy\
            MzQ1Njc4MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4MTIz\
            NDU2NzgxMjM0NTY3ODEyMzQ1Njc4MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4MTIzNDU2NzgxMjM0\
            NTY3ODEyMzQ1Njc4MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4MTIzNDU2NzgxMjM0NTY3ODEyMzQ1\
            Njc4MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4MTIzNDU2\
            NzgxMjM0NTY3ODEyMzQ1Njc4MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4Cg=="
                    .to_string(),
            ),
            Some("MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4".to_string()),
        );
        assert!(result.is_ok());
    }

    #[test]
    //generate_tdx_report_data generated data is 64 bytes
    fn test_generate_tdx_report_data_report_data_is_64_bytes() {
        let report_data_hashed = match Tdx::generate_tdx_report_data(
            Some("MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4".to_string()),
            Some("IXUKoBO1XEFBPwopN4sY".to_string()),
        ) {
            Ok(r) => r,
            Err(_) => todo!(),
        };
        let generated_hash_len = base64::decode(report_data_hashed).unwrap().len();
        assert_eq!(generated_hash_len, 64);
    }
}
