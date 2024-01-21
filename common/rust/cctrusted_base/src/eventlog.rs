use crate::binary_blob::*;
use crate::tcg::EventLogEntry;
use crate::tcg::TcgDigest;
use crate::tcg::TcgEfiSpecIdEvent;
use crate::tcg::TcgEfiSpecIdEventAlgorithmSize;
use crate::tcg::TcgImrEvent;
use crate::tcg::TcgPcClientImrEvent;
use crate::tcg::EV_NO_ACTION;
use anyhow::anyhow;

/***
    TcgEventLog struct.
    This class contains the event logs following TCG specification.
    Attributes:
        data: raw data containing all boot time event logs
        event_logs: all parsed event logs
        count: total number of event logs
*/
pub struct TcgEventLog {
    pub spec_id_header_event: TcgEfiSpecIdEvent,
    pub data: Vec<u8>,
    pub event_logs: Vec<EventLogEntry>,
    pub count: u32,
}

impl TcgEventLog {
    pub fn new(data: Vec<u8>) -> TcgEventLog {
        TcgEventLog {
            spec_id_header_event: TcgEfiSpecIdEvent::new(),
            data,
            event_logs: Vec::new(),
            count: 0,
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
        Parse event log data into TCG compatible forms.
        Go through all event log data and parse the contents accordingly
        Save the parsed event logs into TcgEventLog.
    */
    fn parse(&mut self) -> Result<bool, anyhow::Error> {
        if self.data.is_empty() {
            return Err(anyhow!("[parse] no eventlog data provided"));
        }

        let mut index = 0;
        while index < self.data.len() {
            let start = index;
            let imr = get_u32(self.data[index..index + 4].to_vec());
            index += 4;
            let event_type = get_u32(self.data[index..index + 4].to_vec());
            if imr == 0xFFFFFFFF {
                break;
            }

            if event_type == EV_NO_ACTION {
                match self.parse_spec_id_event_log(self.data[start..].to_vec()) {
                    Ok((spec_id_event, event_len)) => {
                        index = start + event_len as usize;
                        self.event_logs
                            .push(EventLogEntry::TcgPcClientImrEvent(spec_id_event));
                        self.count += 1
                    }
                    Err(e) => {
                        return Err(anyhow!(
                            "[parse] error in parse_spec_id_event_log function {:?}",
                            e
                        ));
                    }
                }
            } else {
                match self.parse_event_log(self.data[start..].to_vec()) {
                    Ok((event_log, event_len)) => {
                        index = start + event_len as usize;
                        self.event_logs.push(EventLogEntry::TcgImrEvent(event_log));
                        self.count += 1
                    }
                    Err(e) => {
                        return Err(anyhow!("[parse] error in parse_event_log function {:?}", e));
                    }
                }
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
            A TcgPcClientImrEvent containing the Specification ID version event
            An int specifying the event size
    */
    fn parse_spec_id_event_log(
        &mut self,
        data: Vec<u8>,
    ) -> Result<(TcgPcClientImrEvent, u32), anyhow::Error> {
        let mut index = 0;

        let imr_index = get_u32(data[index..index + 4].to_vec());
        index += 4;
        let header_imr = imr_index - 1;
        let header_event_type = get_u32(data[index..index + 4].to_vec());
        index += 4;

        let digest = data[index..index + 20].try_into().unwrap();
        index += 20;
        let header_event_size = get_u32(data[index..index + 4].to_vec());
        index += 4;
        let header_event = data[index..index + header_event_size as usize]
            .try_into()
            .unwrap();
        let specification_id_header = TcgPcClientImrEvent {
            imr_index: header_imr,
            event_type: header_event_type,
            digest,
            event_size: header_event_size,
            event: header_event,
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
    fn parse_event_log(&self, data: Vec<u8>) -> Result<(TcgImrEvent, u32), anyhow::Error> {
        let mut index = 0;

        let mut imr_index = get_u32(data[index..index + 4].to_vec());
        index += 4;
        imr_index -= 1;
        let event_type = get_u32(data[index..index + 4].to_vec());
        index += 4;

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
            TcgImrEvent {
                imr_index,
                event_type,
                digests,
                event_size,
                event,
            },
            index.try_into().unwrap(),
        ))
    }
}
