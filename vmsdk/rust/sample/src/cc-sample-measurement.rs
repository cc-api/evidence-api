use cctrusted_base::api::*;
use cctrusted_base::tcg::TcgAlgorithmRegistry;
use cctrusted_vm::sdk::API;

use log::*;

fn main() {
    // set log level
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    // get CVM default algorithm with API "get_default_algorithm"
    info!("call cc trusted API [get_default_algorithm] to get CVM supported algorithm!");
    let defalt_algo = match API::get_default_algorithm() {
        Ok(algorithm) => {
            info!("supported algorithm: {}", algorithm.algo_id_str);
            algorithm
        }
        Err(e) => {
            error!("error get algorithm: {:?}", e);
            return;
        }
    };

    // get number of measurement registers in CVM
    info!("call cc trusted API [get_measurement_count] to get number of measurement registers in CVM!");
    let count = match API::get_measurement_count() {
        Ok(count) => {
            info!("measurement registers count: {}", count);
            count
        }
        Err(e) => {
            error!("error get measurement count: {:?}", e);
            return;
        }
    };

    // retrive and show measurement registers in CVM
    info!("call cc trusted API [get_cc_measurement] to get measurement register content in CVM!");
    for index in 0..count {
        let tcg_digest = match API::get_cc_measurement(index, defalt_algo.algo_id) {
            Ok(tcg_digest) => tcg_digest,
            Err(e) => {
                error!("error get measurement: {:?}", e);
                return;
            }
        };
        info!(
            "show index = {}, algo = {:?}, hash = {:02X?}",
            index,
            tcg_digest.get_algorithm_id_str(),
            tcg_digest.get_hash()
        );
    }
}
