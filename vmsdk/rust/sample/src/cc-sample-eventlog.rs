use cctrusted_base::api::*;
use cctrusted_vm::sdk::API;
use log::*;

fn main() {
    // set log level
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    // retrieve cc eventlog with API "get_cc_eventlog"
    let eventlogs = match API::get_cc_eventlog(Some(1), None) {
        Ok(q) => q,
        Err(e) => {
            error!("error getting TDX report: {:?}", e);
            return;
        }
    };

    info!("event log count: {}", eventlogs.len());
    // for eventlog in &eventlogs {
    //     eventlog.show();
    // }

    // replay cc eventlog with API "replay_cc_eventlog"
    let replay_results = match API::replay_cc_eventlog(eventlogs) {
        Ok(q) => q,
        Err(e) => {
            error!("error replay eventlog: {:?}", e);
            return;
        }
    };

    // show replay results
    for replay_result in replay_results {
        replay_result.show();
    }
}
