/***
 ************************************
 * API get_cc_report() related data *
 ************************************
 */

// input of API get_cc_report()
// this struct is used in vTPM and other TEE scenarios
// e.g.: vTPM may need report based on selective PCRs
pub struct ExtraArgs {}

pub const TYPE_PLAIN: i8 = -1;
pub const TYPE_TDX: i8 = 0;
pub const TYPE_SEV: i8 = 1;
pub const TYPE_CCA: i8 = 2;
pub const TYPE_TPM: i8 = 3;

// return of API get_cc_report()
pub struct CcReport {
    pub cc_report: Vec<u8>,
    pub cc_type: i8,
}

/***
 **************************************
 * API parse_cc_report() related data *
 **************************************
 */
// return of API parse_cc_report() in TDX case
#[derive(Clone)]
pub struct CcParsedTdxReport {
    pub dummy_var1: u8,
    pub dummy_var2: u8,
}

// return of API parse_cc_report() in TPM case
pub struct CcParsedTpmReport {}

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

/***
 ********************************************
 * API get_default_algorithm() related data *
 ********************************************
 */
// return structure for get_default_algorithm
pub struct Algorithm {
    pub algo_id: u8,
    pub algo_id_str: String,
}
