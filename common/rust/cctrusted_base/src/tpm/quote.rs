use crate::api::ParseCcReport;
use crate::api_data::CcReport;

// return of API parse_cc_report()
pub struct TpmQuote {}

impl TpmQuote {
    pub fn parse_tpm_quote(_quote: Vec<u8>) -> Result<TpmQuote, anyhow::Error> {
        todo!()
    }
}

// API function parses raw cc report to TpmQuote struct
impl ParseCcReport<TpmQuote> for CcReport {
    fn parse_cc_report(_report: Vec<u8>) -> Result<TpmQuote, anyhow::Error> {
        todo!()
    }
}
