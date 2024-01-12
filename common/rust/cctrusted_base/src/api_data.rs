use crate::cc_type::TeeType;

/***
 ************************************
 * API get_cc_report() related data *
 ************************************
 */
// input of API get_cc_report()
// this struct is used in vTPM and other CVM scenarios
// e.g.: vTPM may need report based on selective PCRs
pub struct ExtraArgs {}

// return of API get_cc_report()
pub struct CcReport {
    pub cc_report: Vec<u8>,
    pub cc_type: TeeType,
}

/***
 **************************************
 * API parse_cc_report() related data *
 **************************************
*/
/***
  the return data structure is defined in cctrusted_base
  e.g.:
   - cctrusted_base::tdx::quote::TdxQuote;
   - cctrusted_base::tpm::quote::TpmQuote;
*/

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
