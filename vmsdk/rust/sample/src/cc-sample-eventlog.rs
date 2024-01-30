use cctrusted_base::api::*;
use cctrusted_base::tcg::EventLogEntry;
use cctrusted_vm::sdk::API;
use log::*;

fn main() {
    // set log level
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    // retrieve cc eventlog with API "get_cc_eventlog"
    let eventlogs = match API::get_cc_eventlog(Some(0), None) {
        Ok(r) => r,
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
        Ok(r) => r,
        Err(e) => {
            error!("error replay eventlog: {:?}", e);
            return;
        }
    };

    // show replay results
    for replay_result in replay_results {
        replay_result.show();
    }

    // retrieve cc eventlog in batch
    let mut eventlogs1: Vec<EventLogEntry> = Vec::new();
    let mut start = 0;
    let batch_size = 10;
    loop {
        let event_logs = match API::get_cc_eventlog(Some(start), Some(batch_size)) {
            Ok(q) => q,
            Err(e) => {
                error!("error get eventlog: {:?}", e);
                return;
            }
        };
        for event_log in &event_logs {
            eventlogs1.push(event_log.clone());
        }
        if !event_logs.is_empty() {
            start += event_logs.len() as u32;
        } else {
            break;
        }
    }

    info!("event log count: {}", eventlogs1.len());
}
