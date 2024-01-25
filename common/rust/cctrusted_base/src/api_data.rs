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
// the return data structure is defined in cctrusted_base as:
// cctrusted_base::tcg::TcgDigest

/***
 ********************************************
 * API get_cc_eventlog() related data *
 ********************************************
 */
// the return data structure is defined in cctrusted_base as:
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
