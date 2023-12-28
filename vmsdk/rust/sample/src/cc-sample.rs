use cctrusted_base::api::*;
use cctrusted_base::api_data::*;
use cctrusted_base::cc_type::TeeType;
use cctrusted_base::tdx::quote::TdxQuote;
use cctrusted_vm::sdk::API;
use log::*;

fn main() {
    // set log level
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let nonce = "MTIzNDU2Nzg=".to_string();
    let data = "YWJjZGVmZw==".to_string();

    // retrieve cc report with API "get_cc_report"
    info!("call cc trusted API [get_cc_report] to retrieve cc report!");
    let report = match API::get_cc_report(nonce, data, ExtraArgs {}) {
        Ok(q) => q,
        Err(e) => {
            error!("error getting TDX report: {:?}", e);
            return;
        }
    };

    // dump the cc report with API "dump_cc_report"
    info!("call cc trusted API [dump_cc_report] to dump cc report!");
    API::dump_cc_report(&report.cc_report);

    // parse the cc report with API "parse_cc_report"
    if report.cc_type == TeeType::TDX {
        let tdx_quote: TdxQuote = match CcReport::parse_cc_report(report.cc_report) {
            Ok(q) => q,
            Err(e) => {
                error!("error parse tdx quote: {:?}", e);
                return;
            }
        };
        info!(
            "dummy_var1 = {}, dummy_var2 = {}",
            tdx_quote.dummy_var1, tdx_quote.dummy_var2
        );
    }

    // get CVM default algorithm with API "get_default_algorithm"
    info!("call cc trusted API [get_default_algorithm] to get CVM supported algorithm!");
    match API::get_default_algorithm() {
        Ok(algorithm) => {
            info!("supported algorithm: {}", algorithm.algo_id_str);
            ();
        }
        Err(e) => {
            error!("error get algorithm: {:?}", e);
            return;
        }
    };
}
