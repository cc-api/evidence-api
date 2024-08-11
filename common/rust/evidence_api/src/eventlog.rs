use std::io::Read;

use crate::api_data::ReplayResult;
use crate::codecs::VecOf;
use crate::tcg::*;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use hashbrown::HashMap;
use hex;
use log::info;
use scale::Decode;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

/***
*  This is the common struct for tcg event logs to be delivered in different formats.
   Currently TCG supports several event log formats defined in TCG_PCClient Spec,
   Canonical Eventlog Spec, etc.
   This struct provides the functionality to convey event logs in different format
   according to request.

   Attributes:
       rec_num: contains the record number of the event log within the imr index
       imr_index: the index of the register that the event log belongs to
       event_type: event type of the event log
       digests: a list of TcgDigest objects
       event_size: size of the event
       event: raw event information
       extra_info: extra information in the event
*/
#[derive(Clone)]
pub struct TcgEventLog {
    pub rec_num: u32,
    pub imr_index: u32,
    pub event_type: u32,
    pub digests: Vec<TcgDigest>,
    pub event_size: u32,
    pub event: Vec<u8>,
    pub extra_info: HashMap<String, String>,
}

impl TcgEventLog {
    fn format_event_log(&self, parse_format: u8) -> EventLogEntry {
        match parse_format {
            TCG_PCCLIENT_FORMAT => self.to_tcg_pcclient_format(),
            TCG_CANONICAL_FORMAT => self.to_tcg_canonical_format(),
            0_u8 | 3_u8..=u8::MAX => todo!(),
        }
    }

    fn to_tcg_pcclient_format(&self) -> EventLogEntry {
        if self.event_type == EV_NO_ACTION && self.rec_num == 0 && self.imr_index == 0 {
            return EventLogEntry::TcgPcClientImrEvent(TcgPcClientImrEvent {
                imr_index: self.imr_index,
                event_type: self.event_type,
                digest: self.digests[0].hash[0..20].try_into().unwrap(),
                event_size: self.event_size,
                event: self.event.clone(),
            });
        }

        EventLogEntry::TcgImrEvent(TcgImrEvent {
            imr_index: self.imr_index,
            event_type: self.event_type,
            digests: self.digests.clone(),
            event_size: self.event_size,
            event: self.event.clone(),
        })
    }

    fn to_tcg_canonical_format(&self) -> EventLogEntry {
        todo!()
    }

    pub fn show(&self) {
        info!("        --------------------TcgEventLog--------------------------");
        info!("rec_num = {}", self.rec_num);
        info!("imr_index = {}", self.imr_index);
        info!("event_type = {}", self.event_type);
        for index in 0..self.digests.len() {
            info!(
                "digest[{}] = {}",
                self.digests[index].algo_id,
                String::from_utf8_lossy(&self.digests[index].hash)
            );
        }
        info!("event_size = {}", self.event_size);
        info!("event = {}", String::from_utf8_lossy(&self.event));
    }
}

/***
    EventLogs struct.
    This struct contains the all event logs available on the system.

    Attributes:
        boot_time_data: raw data containing all boot time event logs
        runtime_data: raw data containing runtime event logs(now IMA events)
        event_logs: all parsed event logs
        count: total number of event logs
        parse_format: event log format used
*/
#[derive(Clone)]
pub struct EventLogs {
    pub spec_id_header_event: TcgEfiSpecIdEvent,
    pub boot_time_data: Vec<u8>,
    pub run_time_data: Vec<String>,
    pub event_logs: Vec<EventLogEntry>,
    pub count: u32,
    pub parse_format: u8,
    pub event_logs_record_number_list: [u32; 24],
}

impl EventLogs {
    pub fn new(boot_time_data: Vec<u8>, run_time_data: Vec<String>, parse_format: u8) -> EventLogs {
        EventLogs {
            spec_id_header_event: TcgEfiSpecIdEvent::new(),
            boot_time_data,
            run_time_data,
            event_logs: Vec::new(),
            count: 0,
            parse_format,
            event_logs_record_number_list: [0; 24],
        }
    }

    /***
        Collect selected event logs according to user input.
        Args:
            start: index of the first event log to collect, 0 stands for the first event log
            count: total number of event logs to collect
    */
    pub fn select(
        &mut self,
        start: Option<u32>,
        count: Option<u32>,
    ) -> Result<Vec<EventLogEntry>, anyhow::Error> {
        match self.parse() {
            Ok(_) => (),
            Err(e) => {
                return Err(anyhow!("[select] error in parse function {:?}", e));
            }
        }

        let begin = match start {
            Some(s) => {
                if s > self.count {
                    return Err(anyhow!("[select] Invalid input start. Start must be number no bigger than total event log count! Current number of eventlog is {}", self.count));
                } else if s == self.count {
                    return Ok(Vec::new());
                } else {
                    s
                }
            }
            None => 0,
        };

        let end = match count {
            Some(c) => {
                if c == 0 {
                    return Err(anyhow!(
                        "[select] Invalid input count. count must be number larger than 0!"
                    ));
                } else if c + begin > self.count {
                    self.event_logs.len()
                } else {
                    (c + begin).try_into().unwrap()
                }
            }
            None => self.event_logs.len(),
        };

        Ok((self.event_logs[begin as usize..end as usize]).to_vec())
    }

    /***
       Fetch the record number maintained separately by index.
       Increment the number to be prepared for next measurement.

       Args:
           imr_index: the imr index used to fetch certain record number

       Returns:
           The record number
    */
    fn get_record_number(&mut self, imr_index: u32) -> u32 {
        let rec_num = self.event_logs_record_number_list[imr_index as usize];
        self.event_logs_record_number_list[imr_index as usize] += 1;
        rec_num
    }

    /***
        Parse event log data into TCG compatible forms.
        Go through all event log data and parse the contents accordingly
        Save the parsed event logs into EventLogs.
    */
    fn parse(&mut self) -> anyhow::Result<bool> {
        if self.boot_time_data.is_empty() {
            bail!("[parse] no boot time eventlog provided");
        }

        // A buffer used as a input reader
        let buffer = &mut &self.boot_time_data[..];

        while !buffer.is_empty() {
            // A tmp head_buffer is used to peek the imr and event type
            let head_buffer = &mut &buffer[..];
            let imr = u32::decode(head_buffer).context("failed to decode imr")?;
            if imr == 0xFFFFFFFF {
                break;
            }
            let event_type = u32::decode(head_buffer).context("failed to decode event type")?;

            if event_type == EV_NO_ACTION && self.count == 0 {
                let (spec_id_header, spec_id_event) = Self::parse_spec_id_event_log(buffer)
                    .context("[parse] error in parse_spec_id_event_log function")?;
                let todo = "Assign the rec_num";
                self.event_logs
                    .push(spec_id_header.format_event_log(self.parse_format));
                self.spec_id_header_event = spec_id_event;
            } else {
                let event_log = self
                    .parse_event_log(buffer)
                    .context("[parse] error in parse_event_log function")?;
                let todo = "Assign the rec_num";
                self.event_logs
                    .push(event_log.format_event_log(self.parse_format));
            }
            self.count += 1;
        }

        if !self.run_time_data.is_empty() {
            for index in 0..self.run_time_data.len() {
                match self.parse_ima_event_log(&self.run_time_data[index].clone()) {
                    Ok(event_log) => {
                        self.event_logs
                            .push(event_log.format_event_log(self.parse_format));
                        self.count += 1;
                    }
                    Err(e) => {
                        return Err(anyhow!(
                            "[parse] error in parse_ima_event_log function {:?}",
                            e
                        ));
                    }
                };
            }
        }

        Ok(true)
    }

    /***
        Parse TCG specification Id event according to TCG spec at
        https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf.
        Event Structure:
        typedef tdTCG_PCClientPCREvent {
            2735 UINT32 pcrIndex;
            UINT32 eventType;
            BYTE digest[20];
            UINT32 eventDataSize;
            BYTE event[eventDataSize]; //This is actually a TCG_EfiSpecIDEventStruct
        } TCG_PCClientPCREvent;
        Args:
            data: event log data in bytes
        Returns:
            A common TcgEventLog containing the Specification ID version event
            An int specifying the event size
    */
    fn parse_spec_id_event_log(
        input: &mut &[u8],
    ) -> anyhow::Result<(TcgEventLog, TcgEfiSpecIdEvent)> {
        #[derive(Decode)]
        struct Header {
            imr_index: u32,
            header_event_type: u32,
            digest_hash: [u8; 20],
            header_event: VecOf<u32, u8>,
        }

        let decoded_header = Header::decode(input).context("failed to decode log_item")?;
        // Parse EFI Spec Id Event structure
        let spec_id_event =
            TcgEfiSpecIdEvent::decode(input).context("failed to decode TcgEfiSpecIdEvent")?;

        let header_imr = decoded_header
            .imr_index
            .checked_sub(1)
            .ok_or(anyhow!("imr_index overflow"))?;
        let digests = vec![TcgDigest {
            algo_id: TPM_ALG_ERROR,
            hash: decoded_header.digest_hash.to_vec(),
        }];
        let spec_id_header = TcgEventLog {
            rec_num: 0,
            imr_index: header_imr,
            event_type: decoded_header.header_event_type,
            digests,
            event_size: decoded_header.header_event.length(),
            event: decoded_header.header_event.into_inner(),
            extra_info: HashMap::new(),
        };
        Ok((spec_id_header, spec_id_event))
    }

    /***
        Parse TCG event log body as single event log entry (TcgImrEventLogEntry) defined at
        https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
        typedef struct tdTCG_PCR_EVENT2{
            UINT32 pcrIndex;
            UINT32 eventType;
            TPML_DIGEST_VALUES digests;
            UINT32 eventSize;
            BYTE event[eventSize];
        } TCG_PCR_EVENT2;
        Args:
            data: event log data in bytes
        Returns:
            A TcgImrEvent containing the event information
            An int specifying the event size
    */
    fn parse_event_log(&self, input: &mut &[u8]) -> anyhow::Result<TcgEventLog> {
        let mut imr_index = u32::decode(input).context("failed to decode imr_index")?;
        imr_index = imr_index.checked_sub(1).context("invalid imr index")?;
        let event_type = u32::decode(input).context("failed to decode event_type")?;
        // Fetch digest count and get each digest and its algorithm
        let digest_count = u32::decode(input).context("failed to decode digest_count")?;
        let mut digests: Vec<TcgDigest> = Vec::new();
        for _ in 0..digest_count {
            let alg_id = u16::decode(input).context("failed to decode alg_id")?;
            let alg = self
                .spec_id_header_event
                .digest_sizes
                .iter()
                .find(|&x| x.algo_id == alg_id)
                .context("No algorithm with such algo_id")?;
            let digest_size = alg.digest_size;
            let mut digest_data = vec![0; digest_size as usize];
            input
                .read_exact(&mut digest_data)
                .context("failed to read digest_data")?;
            let digest = TcgDigest {
                algo_id: alg_id,
                hash: digest_data,
            };
            digests.push(digest);
        }

        let event = <VecOf<u32, u8>>::decode(input).context("failed to decode event")?;
        Ok(TcgEventLog {
            rec_num: 0, // TODO: alloc the rec_num outside.
            imr_index,
            event_type,
            digests,
            event_size: event.length(),
            event: event.into_inner(),
            extra_info: HashMap::new(),
        })
    }

    /***
       Parse ascii IMA events gathered during runtime.

       Sample event and format:
       IMR index | Template hash | Template name | Event data according to template
       10 1e762ca412a3ef388ddcab416e2eb382d9d1e356 ima-ng sha384:74ccc46104f42db070375e6876a23aeaa3c2ae458888475baaa171c3fb7001b0fc385ed08420d5f60620924fc64d0b80 /etc/lsb-release

       Args:
           event: IMA ascii raw event

       Returns:
           A TcgEventLog object containing the ima event log
    */
    fn parse_ima_event_log(&mut self, data: &str) -> Result<TcgEventLog, anyhow::Error> {
        /*  after the split, the elements vec has following mapping:
               elements[0] => IMR index
               elements[1] => Template hash
               elements[2] => Template name
               elements[3] to end of vec => Event data according to template
        */
        let elements: Vec<&str> = data.trim_matches(' ').split(' ').collect();

        let imr_index: u32 = elements[0].parse().unwrap();
        let rec_num = self.get_record_number(imr_index);

        let event = elements[3..].join(" ").as_bytes().to_vec();
        let event_size = event.len() as u32;

        let mut digests: Vec<TcgDigest> = Vec::new();
        let digest_size = elements[1].len() / 2;
        let algo_id = TcgDigest::get_algorithm_id_from_digest_size(digest_size.try_into().unwrap());
        let digest = TcgDigest {
            algo_id,
            hash: hex::decode(elements[1]).expect("Decoding hash string from IMA record failed"),
        };
        digests.push(digest);

        let mut extra_info = HashMap::new();
        extra_info.insert("template_name".to_string(), elements[2].to_string());

        Ok(TcgEventLog {
            rec_num,
            imr_index,
            event_type: IMA_MEASUREMENT_EVENT,
            digests,
            event_size,
            event,
            extra_info,
        })
    }
    /***
       Replay event logs by IMR index.
       Returns:
           A struct containing the replay result arranged by IMR index and hash algorithm.
           Layer 1 key of the struct is the IMR index, the value is another dict which using the
           hash algorithm as the key and the replayed measurement as value.
           Sample results:
               [
                   0: [{ 4: <measurement_replayed>},{ 12: <measurement_replayed>},]
                   1: { 12: <measurement_replayed>},
               ]
    */
    pub fn replay(eventlogs: Vec<EventLogEntry>) -> Result<Vec<ReplayResult>, anyhow::Error> {
        let mut replay_results: Vec<ReplayResult> = Vec::new();

        for event_log in eventlogs {
            match event_log {
                EventLogEntry::TcgImrEvent(tcg_imr_event) => {
                    if tcg_imr_event.event_type == EV_NO_ACTION {
                        continue;
                    }
                    let imr_index = tcg_imr_event.imr_index;
                    for digest in tcg_imr_event.digests {
                        let algo_id = digest.algo_id;
                        let hash = digest.hash;
                        let digest_size = TcgDigest::get_digest_size_from_algorithm_id(algo_id);

                        let mut imr_pos = usize::MAX;
                        let mut algo_pos = usize::MAX;
                        for index1 in 0..replay_results.len() {
                            if replay_results[index1].imr_index == imr_index {
                                imr_pos = index1;
                            }
                        }

                        if imr_pos == usize::MAX {
                            replay_results.push(ReplayResult {
                                imr_index,
                                digests: Vec::new(),
                            });
                            imr_pos = replay_results.len() - 1;
                        } else {
                            for index2 in 0..replay_results[imr_pos].digests.len() {
                                if digest.algo_id == algo_id {
                                    algo_pos = index2;
                                }
                            }
                        }

                        if algo_pos == usize::MAX {
                            replay_results[imr_pos].digests.push(TcgDigest {
                                algo_id,
                                hash: vec![0; digest_size.into()],
                            });
                            algo_pos = replay_results[imr_pos].digests.len() - 1;
                        }

                        let hash_input_data =
                            [replay_results[imr_pos].digests[algo_pos].hash.clone(), hash].concat();

                        match algo_id {
                            TPM_ALG_SHA1 => {
                                let mut algo_hasher = Sha1::new();
                                algo_hasher.update(hash_input_data);
                                replay_results[imr_pos].digests[algo_pos].hash =
                                    algo_hasher.finalize().to_vec();
                            }
                            TPM_ALG_SHA256 => {
                                let mut algo_hasher = Sha256::new();
                                algo_hasher.update(hash_input_data);
                                replay_results[imr_pos].digests[algo_pos].hash =
                                    algo_hasher.finalize().to_vec();
                            }
                            TPM_ALG_SHA384 => {
                                let mut algo_hasher = Sha384::new();
                                algo_hasher.update(hash_input_data);
                                replay_results[imr_pos].digests[algo_pos].hash =
                                    algo_hasher.finalize().to_vec();
                            }
                            TPM_ALG_SHA512 => {
                                let mut algo_hasher = Sha512::new();
                                algo_hasher.update(hash_input_data);
                                replay_results[imr_pos].digests[algo_pos].hash =
                                    algo_hasher.finalize().to_vec();
                            }
                            0_u16..=3_u16 | 5_u16..=10_u16 | 14_u16..=u16::MAX => (),
                        }
                    }
                }
                EventLogEntry::TcgPcClientImrEvent(_) => (), // Skip TcgPcClientImrEvent during replay
                EventLogEntry::TcgCanonicalEvent(_) => todo!(),
            }
        }
        Ok(replay_results)
    }
}

impl ReplayResult {
    pub fn show(&self) {
        info!(
            "-------------------------------Replay Result of IMR[{}]-----------------------------",
            self.imr_index
        );
        for digest in &self.digests {
            info!("Algorithm: {}", digest.get_algorithm_id_str());
            info!("Digest: {:02X?}", digest.hash);
        }
    }
}
