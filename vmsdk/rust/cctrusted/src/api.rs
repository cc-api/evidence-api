use anyhow::*;
use std::mem;
use std::result::Result;
use std::result::Result::Ok;

use cctrusted_base::binary_blob::dump_data;
use cctrusted_base::cc_type::CcType;
use cctrusted_base::eventlog::TcgEventLog;
use cctrusted_base::tcg::{TcgDigest, ALGO_NAME_MAP};
use cctrusted_base::tdx::quote::TdxQuote;
use cctrusted_base::tpm::quote::TpmQuote;

use crate::api_data::*;

/***
    Get the cc report for given nonce and data.

    The cc report is signing of attestation data (IMR values or hashes of IMR
    values), made by a trusted foundation (TPM) using a key trusted by the
    verifier.

    Different trusted foundation may use different cc report format.

    Args:
        nonce (String): against replay attacks
        data (String): user data
        extraArgs: for TPM, it will be given list of IMR/PCRs

    Returns:
        The cc report byte array or error information
*/
pub fn get_cc_report(
    nonce: String,
    data: String,
    _extra_args: ExtraArgs,
) -> Result<CcReport, anyhow::Error> {
    match CcType::build_tee() {
        Ok(mut tee) => {
            // call tee trait defined methods
            tee.dump();
            Ok(CcReport {
                cc_report: match tee.process_cc_report(nonce, data) {
                    Ok(r) => r,
                    Err(e) => {
                        return Err(anyhow!("[get_cc_report] error get cc report: {:?}", e));
                    }
                },
                cc_type: tee.get_cc_type().tee_type as i8,
            })
        }
        Err(e) => return Err(anyhow!("[get_cc_report] error create tee: {:?}", e)),
    }
}

pub fn dump_cc_report(report: &Vec<u8>) {
    dump_data(report)
}

/***
   Get measurement register according to given selected index and algorithms

   Each trusted foundation in CC environment provides the multiple measurement
   registers, the count is update to ``get_measurement_count()``. And for each
   measurement register, it may provides multiple digest for different algorithms.

   Args:
       index (u8): the index of measurement register,
       algo_id (u8): the alrogithms ID

   Returns:
       TcgDigest struct
*/
pub fn get_cc_measurement(_index: u8, _algo_id: u8) -> TcgDigest {
    todo!()
}

/***
    Get eventlog for given index and count.

    TCG log in Eventlog. Verify to spoof events in the TCG log, hence defeating
    remotely-attested measured-boot.

    To measure the full CC runtime environment, the eventlog may include addtional
    OS type and cloud native type event beyond the measured-boot.

    Returns:
        TcgEventLog struct
*/
pub fn get_cc_eventlog(_start: u16, _count: u16) -> TcgEventLog {
    todo!()
}

/***
    Get the default Digest algorithms supported by trusted foundation.

    Different trusted foundation may support different algorithms, for example
    the Intel TDX use SHA384, TPM uses SHA256.

    Beyond the default digest algorithm, some trusted foundation like TPM
    may support multiple algorithms.

    Returns:
        The Algorithm struct

*/
pub fn get_default_algorithm() -> Result<Algorithm, anyhow::Error> {
    match CcType::build_tee() {
        Ok(tee) => {
            // call tee trait defined methods
            let algo_id = tee.get_algorithm_id();
            Ok(Algorithm {
                algo_id: algo_id,
                algo_id_str: ALGO_NAME_MAP.get(&algo_id).unwrap().to_owned(),
            })
        }
        Err(e) => {
            return Err(anyhow!(
                "[get_default_algorithm] error get algorithm: {:?}",
                e
            ))
        }
    }
}

// this function parses cc report to the TDX quote struct
impl ParseCcReport<CcParsedTdxReport> for CcReport {
    fn parse_cc_report(report: Vec<u8>) -> Result<CcParsedTdxReport, anyhow::Error> {
        match TdxQuote::parse_tdx_quote(report) {
            Ok(tdx_quote) => unsafe {
                let report: &CcParsedTdxReport = mem::transmute(&tdx_quote);
                Ok(report.clone())
            },
            Err(e) => return Err(anyhow!("[parse_cc_report] error parse tdx quote: {:?}", e)),
        }
    }
}

// this function parses cc report to the TPM quote struct
impl ParseCcReport<TpmQuote> for CcReport {
    fn parse_cc_report(_report: Vec<u8>) -> Result<TpmQuote, anyhow::Error> {
        todo!()
    }
}
