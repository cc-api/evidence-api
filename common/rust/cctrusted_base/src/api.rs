use crate::api_data::Algorithm;
use crate::api_data::*;
use crate::eventlog::TcgEventLog;
use crate::tcg::TcgDigest;
use crate::tdx::quote::TdxQuote;
use crate::tpm::quote::TpmQuote;
use anyhow::*;
use core::mem;
use core::result::Result;
use core::result::Result::Ok;

pub trait CCTrustedApi {
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
    fn get_cc_report(
        nonce: String,
        data: String,
        _extra_args: ExtraArgs,
    ) -> Result<CcReport, anyhow::Error>;

    /***
        Dump the given cc report in hex and char format

        Args:
            report (Vec<u8>): cc report to be printed

        Returns:
            None
    */
    fn dump_cc_report(report: &Vec<u8>);

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
    fn get_cc_measurement(_index: u8, _algo_id: u8) -> TcgDigest;

    /***
        Get eventlog for given index and count.

        TCG log in Eventlog. Verify to spoof events in the TCG log, hence defeating
        remotely-attested measured-boot.

        To measure the full CC runtime environment, the eventlog may include addtional
        OS type and cloud native type event beyond the measured-boot.

        Returns:
            TcgEventLog struct
    */
    fn get_cc_eventlog(_start: u16, _count: u16) -> TcgEventLog;

    /***
        Get the default Digest algorithms supported by trusted foundation.

        Different trusted foundation may support different algorithms, for example
        the Intel TDX use SHA384, TPM uses SHA256.

        Beyond the default digest algorithm, some trusted foundation like TPM
        may support multiple algorithms.

        Returns:
            The Algorithm struct

    */
    fn get_default_algorithm() -> Result<Algorithm, anyhow::Error>;
}

/***
    trait to be implemented for cc report parsing.

    the cooresponding implementation of parse_cc_report will be called according to
    intented return format and the return of the trait function depends on
    the type of cc report, e.g.: TdxQuote, TpmQuote and etc.

    TDX quote parsing Example:
    if following is provided:
        let tdx_quote: TdxQuote = parse_cc_report(cc_report_str);
    then this implementation in api.rs will be called:
        fn parse_cc_report(report: Vec<u8>) -> Result<TdxQuote, anyhow::Error>;
*/
pub trait ParseCcReport<T> {
    fn parse_cc_report(_report: Vec<u8>) -> Result<T, anyhow::Error>;
}

// API function parses raw cc report to TdxQuote struct
impl ParseCcReport<TdxQuote> for CcReport {
    fn parse_cc_report(report: Vec<u8>) -> Result<TdxQuote, anyhow::Error> {
        match TdxQuote::parse_tdx_quote(report) {
            Ok(tdx_quote) => unsafe {
                let report: &TdxQuote = mem::transmute(&tdx_quote);
                Ok(report.clone())
            },
            Err(e) => Err(anyhow!("[parse_cc_report] error parse tdx quote: {:?}", e)),
        }
    }
}

// API function parses raw cc report to TpmQuote struct
impl ParseCcReport<TpmQuote> for CcReport {
    fn parse_cc_report(_report: Vec<u8>) -> Result<TpmQuote, anyhow::Error> {
        todo!()
    }
}
