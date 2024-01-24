use crate::binary_blob::*;
use crate::tcg::*;
use anyhow::anyhow;
use hashbrown::HashMap;

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
        if self.event_type == EV_NO_ACTION {
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
            start: index of the first event log to collect
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
                if s == 0 || s >= self.count {
                    return Err(anyhow!("[select] Invalid input start. Start must be number larger than 0 and smaller than total event log count."));
                }
                s - 1
            }
            None => 0,
        };

        let end = match count {
            Some(c) => {
                if c == 0 || c >= self.count {
                    return Err(anyhow!("[select] Invalid input count. count must be number larger than 0 and smaller than total event log count."));
                }
                (c + begin).try_into().unwrap()
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
    fn parse(&mut self) -> Result<bool, anyhow::Error> {
        if self.boot_time_data.is_empty() {
            return Err(anyhow!("[parse] no boot time eventlog provided"));
        }

        let mut index = 0;
        while index < self.boot_time_data.len() {
            let start = index;
            let imr = get_u32(self.boot_time_data[index..index + 4].to_vec());
            index += 4;
            let event_type = get_u32(self.boot_time_data[index..index + 4].to_vec());
            if imr == 0xFFFFFFFF {
                break;
            }

            if event_type == EV_NO_ACTION {
                match self.parse_spec_id_event_log(self.boot_time_data[start..].to_vec()) {
                    Ok((spec_id_event, event_len)) => {
                        index = start + event_len as usize;
                        self.event_logs
                            .push(spec_id_event.format_event_log(self.parse_format));
                        self.count += 1;
                    }
                    Err(e) => {
                        return Err(anyhow!(
                            "[parse] error in parse_spec_id_event_log function {:?}",
                            e
                        ));
                    }
                }
            } else {
                match self.parse_event_log(self.boot_time_data[start..].to_vec()) {
                    Ok((event_log, event_len)) => {
                        index = start + event_len as usize;
                        self.event_logs
                            .push(event_log.format_event_log(self.parse_format));
                        self.count += 1;
                    }
                    Err(e) => {
                        return Err(anyhow!("[parse] error in parse_event_log function {:?}", e));
                    }
                }
            }
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
        &mut self,
        data: Vec<u8>,
    ) -> Result<(TcgEventLog, u32), anyhow::Error> {
        let mut index = 0;

        let imr_index = get_u32(data[index..index + 4].to_vec());
        index += 4;
        let header_imr = imr_index - 1;
        let header_event_type = get_u32(data[index..index + 4].to_vec());
        index += 4;

        let rec_num = self.get_record_number(header_imr);

        let digest_hash = data[index..index + 20].try_into().unwrap();
        index += 20;
        let mut digests: Vec<TcgDigest> = Vec::new();
        let digest = TcgDigest {
            algo_id: TPM_ALG_ERROR,
            hash: digest_hash,
        };
        digests.push(digest);

        let header_event_size = get_u32(data[index..index + 4].to_vec());
        index += 4;
        let header_event = data[index..index + header_event_size as usize]
            .try_into()
            .unwrap();
        let specification_id_header = TcgEventLog {
            rec_num,
            imr_index: header_imr,
            event_type: header_event_type,
            digests,
            event_size: header_event_size,
            event: header_event,
            extra_info: HashMap::new(),
        };

        // Parse EFI Spec Id Event structure
        let spec_id_signature = data[index..index + 16].try_into().unwrap();
        index += 16;
        let spec_id_platform_cls = get_u32(data[index..index + 4].to_vec());
        index += 4;
        let spec_id_version_minor = get_u8(data[index..index + 1].to_vec());
        index += 1;
        let spec_id_version_major = get_u8(data[index..index + 1].to_vec());
        index += 1;
        let spec_id_errata = get_u8(data[index..index + 1].to_vec());
        index += 1;
        let spec_id_uint_size = get_u8(data[index..index + 1].to_vec());
        index += 1;
        let spec_id_num_of_algo = get_u32(data[index..index + 4].to_vec());
        index += 4;
        let mut spec_id_digest_sizes: Vec<TcgEfiSpecIdEventAlgorithmSize> = Vec::new();

        for _ in 0..spec_id_num_of_algo {
            let algo_id = get_u16(data[index..index + 2].to_vec());
            index += 2;
            let digest_size = get_u16(data[index..index + 2].to_vec());
            index += 2;
            spec_id_digest_sizes.push(TcgEfiSpecIdEventAlgorithmSize {
                algo_id,
                digest_size: digest_size.into(),
            });
        }

        let spec_id_vendor_size = get_u8(data[index..index + 1].to_vec());
        index += 1;
        let mut spec_id_vendor_info = Vec::new();
        if spec_id_vendor_size > 0 {
            spec_id_vendor_info = data[index..index + spec_id_vendor_size as usize]
                .try_into()
                .unwrap();
        }
        index += spec_id_vendor_size as usize;

        self.spec_id_header_event = TcgEfiSpecIdEvent {
            signature: spec_id_signature,
            platform_class: spec_id_platform_cls,
            spec_version_minor: spec_id_version_minor,
            spec_version_major: spec_id_version_major,
            spec_errata: spec_id_errata,
            uintn_ize: spec_id_uint_size,
            number_of_algorithms: spec_id_num_of_algo,
            digest_sizes: spec_id_digest_sizes,
            vendor_info_size: spec_id_vendor_size,
            vendor_info: spec_id_vendor_info,
        };

        Ok((specification_id_header, index.try_into().unwrap()))
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
    fn parse_event_log(&mut self, data: Vec<u8>) -> Result<(TcgEventLog, u32), anyhow::Error> {
        let mut index = 0;

        let mut imr_index = get_u32(data[index..index + 4].to_vec());
        index += 4;
        imr_index -= 1;
        let event_type = get_u32(data[index..index + 4].to_vec());
        index += 4;

        let rec_num = self.get_record_number(imr_index);

        // Fetch digest count and get each digest and its algorithm
        let digest_count = get_u32(data[index..index + 4].to_vec());
        index += 4;
        let mut digests: Vec<TcgDigest> = Vec::new();
        for _ in 0..digest_count {
            let alg_id = get_u16(data[index..index + 2].to_vec());
            index += 2;
            let mut pos = 0;

            while pos < self.spec_id_header_event.digest_sizes.len() {
                if self.spec_id_header_event.digest_sizes[pos].algo_id == alg_id {
                    break;
                }
                pos += 1;
            }

            if pos == self.spec_id_header_event.digest_sizes.len() {
                return Err(anyhow!(
                    "[parse_event_log] No algorithm with such algo_id {}",
                    alg_id
                ));
            }

            let alg = &self.spec_id_header_event.digest_sizes[pos];
            let digest_size = alg.digest_size;
            let digest_data = data[index..index + digest_size as usize]
                .try_into()
                .unwrap();
            index += digest_size as usize;
            let digest = TcgDigest {
                algo_id: alg_id,
                hash: digest_data,
            };
            digests.push(digest);
        }

        let event_size = get_u32(data[index..index + 4].to_vec());
        index += 4;
        let event = data[index..index + event_size as usize].try_into().unwrap();
        index += event_size as usize;

        Ok((
            TcgEventLog {
                rec_num,
                imr_index,
                event_type,
                digests,
                event_size,
                event,
                extra_info: HashMap::new(),
            },
            index.try_into().unwrap(),
        ))
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
            hash: elements[1].as_bytes().to_vec(),
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
}
