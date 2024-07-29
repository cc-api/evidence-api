use crate::cc_type::TeeType;
use crate::tcg::TcgDigest;

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
#[derive(Default)]
pub struct CcReport {
    pub cc_report: Vec<u8>,
    pub cc_type: TeeType,
    pub cc_aux_blob: Option<Vec<u8>>,
    pub cc_report_generation: Option<u32>,
    pub cc_provider: Option<String>,
}

/***
 **************************************
 * API parse_cc_report() related data *
 **************************************
*/
/***
  the return data structure is defined in evidence_api
  e.g.:
   - evidence_api::tdx::quote::TdxQuote;
   - evidence_api::tpm::quote::TpmQuote;
*/

/***
 ********************************************
 * API get_default_algorithm() related data *
 ********************************************
 */
// return structure for get_default_algorithm
pub struct Algorithm {
    pub algo_id: u16,
    pub algo_id_str: String,
}

/***
 ********************************************
 * API get_measurement_count() related data *
 ********************************************
 */
// return number of measurement registers in a CVM

/***
 ********************************************
 * API get_cc_measurement() related data *
 ********************************************
 */
// the return data structure is defined in evidence_api as:
// evidence_api::tcg::TcgDigest

/***
 ********************************************
 * API get_cc_eventlog() related data *
 ********************************************
 */
// the return data structure is defined in evidence_api as:
// crate::tcg::EventLogEntry

/***
 ********************************************
 * API replay_eventlog() related data *
 ********************************************
 */
pub struct ReplayResult {
    pub imr_index: u32,
    pub digests: Vec<TcgDigest>,
}
