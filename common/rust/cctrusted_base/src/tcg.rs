use crate::binary_blob::dump_data;
use hashbrown::HashMap;
use log::info;

pub const TPM_ALG_ERROR: u16 = 0x0;
pub const TPM_ALG_RSA: u16 = 0x1;
pub const TPM_ALG_SHA1: u16 = 0x4;
pub const TPM_ALG_SHA256: u16 = 0xB;
pub const TPM_ALG_SHA384: u16 = 0xC;
pub const TPM_ALG_SHA512: u16 = 0xD;
pub const TPM_ALG_ECDSA: u16 = 0x18;

// hash algorithm ID to algorithm name string map
lazy_static! {
    pub static ref ALGO_NAME_MAP: HashMap<u16, String> = {
        let mut map: HashMap<u16, String> = HashMap::new();
        map.insert(TPM_ALG_ERROR, "TPM_ALG_ERROR".to_string());
        map.insert(TPM_ALG_RSA, "TPM_ALG_RSA".to_string());
        map.insert(TPM_ALG_SHA1, "TPM_ALG_SHA1".to_string());
        map.insert(TPM_ALG_SHA256, "TPM_ALG_SHA256".to_string());
        map.insert(TPM_ALG_SHA384, "TPM_ALG_SHA384".to_string());
        map.insert(TPM_ALG_SHA512, "TPM_ALG_SHA512".to_string());
        map.insert(TPM_ALG_ECDSA, "TPM_ALG_ECDSA".to_string());
        map
    };
}

// this trait retrieve tcg standard algorithm name in string
pub trait TcgAlgorithmRegistry {
    fn get_algorithm_id(&self) -> u16;
    fn get_algorithm_id_str(&self) -> String;
}

// digest format: (algo id, hash value)
#[derive(Clone)]
pub struct TcgDigest {
    pub algo_id: u16,
    pub hash: Vec<u8>,
}

impl TcgDigest {
    pub fn show(&self) {
        info!("show data in struct TcgDigest");
        info!(
            "algo = {}",
            ALGO_NAME_MAP.get(&self.algo_id).unwrap().to_owned()
        );
        info!("hash = {:02X?}", self.hash);
    }

    pub fn get_hash(&self) -> Vec<u8> {
        self.hash.clone()
    }
}

impl TcgAlgorithmRegistry for TcgDigest {
    fn get_algorithm_id(&self) -> u16 {
        self.algo_id
    }

    fn get_algorithm_id_str(&self) -> String {
        ALGO_NAME_MAP.get(&self.algo_id).unwrap().to_owned()
    }
}

// traits a Tcg IMR should have
pub trait TcgIMR {
    fn max_index() -> u8;
    fn get_index(&self) -> u8;
    fn get_tcg_digest(&self, algo_id: u16) -> TcgDigest;
    fn is_valid_index(index: u8) -> Result<bool, anyhow::Error>;
    fn is_valid_algo(algo_id: u16) -> Result<bool, anyhow::Error>;
}

/***
    TCG EventType defined at
    https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf
*/
pub const EV_PREBOOT_CERT: u32 = 0x0;
pub const EV_POST_CODE: u32 = 0x1;
pub const EV_UNUSED: u32 = 0x2;
pub const EV_NO_ACTION: u32 = 0x3;
pub const EV_SEPARATOR: u32 = 0x4;
pub const EV_ACTION: u32 = 0x5;
pub const EV_EVENT_TAG: u32 = 0x6;
pub const EV_S_CRTM_CONTENTS: u32 = 0x7;
pub const EV_S_CRTM_VERSION: u32 = 0x8;
pub const EV_CPU_MICROCODE: u32 = 0x9;
pub const EV_PLATFORM_CONFIG_FLAGS: u32 = 0xa;
pub const EV_TABLE_OF_DEVICES: u32 = 0xb;
pub const EV_COMPACT_HASH: u32 = 0xc;
pub const EV_IPL: u32 = 0xd;
pub const EV_IPL_PARTITION_DATA: u32 = 0xe;
pub const EV_NONHOST_CODE: u32 = 0xf;
pub const EV_NONHOST_CONFIG: u32 = 0x10;
pub const EV_NONHOST_INFO: u32 = 0x11;
pub const EV_OMIT_BOOT_DEVICE_EVENTS: u32 = 0x12;

pub const EV_EFI_EVENT_BASE: u32 = 0x80000000;
pub const EV_EFI_VARIABLE_DRIVER_CONFIG: u32 = EV_EFI_EVENT_BASE + 0x1;
pub const EV_EFI_VARIABLE_BOOT: u32 = EV_EFI_EVENT_BASE + 0x2;
pub const EV_EFI_BOOT_SERVICES_APPLICATION: u32 = EV_EFI_EVENT_BASE + 0x3;
pub const EV_EFI_BOOT_SERVICES_DRIVER: u32 = EV_EFI_EVENT_BASE + 0x4;
pub const EV_EFI_RUNTIME_SERVICES_DRIVER: u32 = EV_EFI_EVENT_BASE + 0x5;
pub const EV_EFI_GPT_EVENT: u32 = EV_EFI_EVENT_BASE + 0x6;
pub const EV_EFI_ACTION: u32 = EV_EFI_EVENT_BASE + 0x7;
pub const EV_EFI_PLATFORM_FIRMWARE_BLOB: u32 = EV_EFI_EVENT_BASE + 0x8;
pub const EV_EFI_HANDOFF_TABLES: u32 = EV_EFI_EVENT_BASE + 0x9;
pub const EV_EFI_VARIABLE_AUTHORITY: u32 = EV_EFI_EVENT_BASE + 0x10;

lazy_static! {
    pub static ref TCG_EVENT_TYPE_NAME_MAP: HashMap<u32, String> = {
        let mut map: HashMap<u32, String> = HashMap::new();
        map.insert(EV_PREBOOT_CERT, "EV_PREBOOT_CERT".to_string());
        map.insert(EV_POST_CODE, "EV_POST_CODE".to_string());
        map.insert(EV_UNUSED, "EV_UNUSED".to_string());
        map.insert(EV_NO_ACTION, "EV_NO_ACTION".to_string());
        map.insert(EV_SEPARATOR, "EV_SEPARATOR".to_string());
        map.insert(EV_ACTION, "EV_ACTION".to_string());
        map.insert(EV_EVENT_TAG, "EV_EVENT_TAG".to_string());
        map.insert(EV_S_CRTM_CONTENTS, "EV_S_CRTM_CONTENTS".to_string());
        map.insert(EV_S_CRTM_VERSION, "EV_S_CRTM_VERSION".to_string());
        map.insert(EV_CPU_MICROCODE, "EV_CPU_MICROCODE".to_string());
        map.insert(
            EV_PLATFORM_CONFIG_FLAGS,
            "EV_PLATFORM_CONFIG_FLAGS".to_string(),
        );
        map.insert(EV_TABLE_OF_DEVICES, "EV_TABLE_OF_DEVICES".to_string());
        map.insert(EV_COMPACT_HASH, "EV_COMPACT_HASH".to_string());
        map.insert(EV_IPL, "EV_IPL".to_string());
        map.insert(EV_IPL_PARTITION_DATA, "EV_IPL_PARTITION_DATA".to_string());
        map.insert(EV_NONHOST_CODE, "EV_NONHOST_CODE".to_string());
        map.insert(EV_NONHOST_CONFIG, "EV_NONHOST_CONFIG".to_string());
        map.insert(EV_NONHOST_INFO, "EV_NONHOST_INFO".to_string());
        map.insert(
            EV_OMIT_BOOT_DEVICE_EVENTS,
            "EV_OMIT_BOOT_DEVICE_EVENTS".to_string(),
        );
        map.insert(EV_EFI_EVENT_BASE, "EV_EFI_EVENT_BASE".to_string());
        map.insert(
            EV_EFI_VARIABLE_DRIVER_CONFIG,
            "EV_EFI_VARIABLE_DRIVER_CONFIG".to_string(),
        );
        map.insert(EV_EFI_VARIABLE_BOOT, "EV_EFI_VARIABLE_BOOT".to_string());
        map.insert(
            EV_EFI_BOOT_SERVICES_APPLICATION,
            "EV_EFI_BOOT_SERVICES_APPLICATION".to_string(),
        );
        map.insert(
            EV_EFI_BOOT_SERVICES_DRIVER,
            "EV_EFI_BOOT_SERVICES_DRIVER".to_string(),
        );
        map.insert(
            EV_EFI_RUNTIME_SERVICES_DRIVER,
            "EV_EFI_RUNTIME_SERVICES_DRIVER".to_string(),
        );
        map.insert(EV_EFI_GPT_EVENT, "EV_EFI_GPT_EVENT".to_string());
        map.insert(EV_EFI_ACTION, "EV_EFI_ACTION".to_string());
        map.insert(
            EV_EFI_PLATFORM_FIRMWARE_BLOB,
            "EV_EFI_PLATFORM_FIRMWARE_BLOB".to_string(),
        );
        map.insert(EV_EFI_HANDOFF_TABLES, "EV_EFI_HANDOFF_TABLES".to_string());
        map.insert(
            EV_EFI_VARIABLE_AUTHORITY,
            "EV_EFI_VARIABLE_AUTHORITY".to_string(),
        );
        map
    };
}

#[derive(Clone)]
pub struct TcgEventType {}

impl TcgEventType {
    pub fn get_event_type_string(event_type: u32) -> String {
        match TCG_EVENT_TYPE_NAME_MAP.get(&event_type) {
            Some(str) => str.to_string(),
            None => "UNKNOWN".to_string(),
        }
    }
}

/***
    TCG IMR Event struct defined at
    https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf.
    Definition:
    typedef struct tdTCG_PCR_EVENT2{
        UINT32 pcrIndex;
        UINT32 eventType;
        TPML_DIGEST_VALUES digests;
        UINT32 eventSize;
        BYTE event[eventSize];
    } TCG_PCR_EVENT2;
*/
#[derive(Clone)]
pub struct TcgImrEvent {
    pub imr_index: u32,
    pub event_type: u32,
    pub digests: Vec<TcgDigest>,
    pub event_size: u32,
    pub event: Vec<u8>,
}

/***
    TCG TCG_PCClientPCREvent defined at
    https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf.
    Definition:
    typedef tdTCG_PCClientPCREvent {
        UINT32 pcrIndex;
        UINT32 eventType;
        BYTE digest[20];
        UINT32 eventDataSize;
        BYTE event[eventDataSize]; //This is actually a TCG_EfiSpecIDEventStruct
    } TCG_PCClientPCREvent;
*/
#[derive(Clone)]
pub struct TcgPcClientImrEvent {
    pub imr_index: u32,
    pub event_type: u32,
    pub digest: [u8; 20],
    pub event_size: u32,
    pub event: Vec<u8>,
}

/***
    TCG TCG_EfiSpecIDEventStruct defined at
    https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf.
    Definition:
    typedef struct tdTCG_EfiSpecIdEventStruct {
        BYTE[16] signature;
        UINT32 platformClass;
        UINT8 specVersionMinor;
        UINT8 specVersionMajor;
        UINT8 specErrata;
        UINT8 uintnSize;
        UINT32 numberOfAlgorithms;
        TCG_EfiSpecIdEventAlgorithmSize[numberOfAlgorithms] digestSizes;
        UINT8 vendorInfoSize;
        BYTE[VendorInfoSize] vendorInfo;
    } TCG_EfiSpecIDEventStruct;
*/
#[derive(Clone)]
pub struct TcgEfiSpecIdEvent {
    pub signature: [u8; 16],
    pub platform_class: u32,
    pub spec_version_minor: u8,
    pub spec_version_major: u8,
    pub spec_errata: u8,
    pub uintn_ize: u8,
    pub number_of_algorithms: u32,
    pub digest_sizes: Vec<TcgEfiSpecIdEventAlgorithmSize>,
    pub vendor_info_size: u8,
    pub vendor_info: Vec<u8>,
}

impl Default for TcgEfiSpecIdEvent {
    fn default() -> Self {
        Self::new()
    }
}

impl TcgEfiSpecIdEvent {
    pub fn new() -> TcgEfiSpecIdEvent {
        TcgEfiSpecIdEvent {
            signature: [0; 16],
            platform_class: 0,
            spec_version_minor: 0,
            spec_version_major: 0,
            spec_errata: 0,
            uintn_ize: 0,
            number_of_algorithms: 0,
            digest_sizes: Vec::new(),
            vendor_info_size: 0,
            vendor_info: Vec::new(),
        }
    }
}

/***
    TCG TCG_EfiSpecIdEventAlgorithmSize defined at
    https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf.
    Definiton:
    typedef struct tdTCG_EfiSpecIdEventAlgorithmSize {
        UINT16 algorithmId;
        UINT16 digestSize;
    } TCG_EfiSpecIdEventAlgorithmSize;
*/
#[derive(Clone)]
pub struct TcgEfiSpecIdEventAlgorithmSize {
    pub algo_id: u16,
    pub digest_size: u32,
}

#[derive(Clone)]
pub enum EventLogEntry {
    TcgImrEvent(TcgImrEvent),
    TcgPcClientImrEvent(TcgPcClientImrEvent),
}

impl EventLogEntry {
    pub fn show(&self) {
        match self {
            EventLogEntry::TcgImrEvent(tcg_imr_event) => &tcg_imr_event.show(),
            EventLogEntry::TcgPcClientImrEvent(tcg_pc_client_imr_event) => {
                &tcg_pc_client_imr_event.show()
            }
        };
    }
}

impl TcgImrEvent {
    pub fn show(&self) {
        info!(
            "        -------------------------------Event Log Entry-----------------------------"
        );
        info!("        IMR               : {}", self.imr_index);
        info!(
            "        Type              : {:02X?} ({})",
            self.event_type,
            &TcgEventType::get_event_type_string(self.event_type)
        );

        for digest_index in 0..self.digests.len() {
            info!(
                "        Algorithm_id[{}]   : {} {}",
                digest_index,
                self.digests[digest_index].algo_id,
                ALGO_NAME_MAP
                    .get(&self.digests[digest_index].algo_id)
                    .unwrap()
                    .to_owned()
            );
            info!("        Digest[{}]:", digest_index);
            dump_data(&self.digests[digest_index].hash);
        }
        info!("        Event:");
        dump_data(&self.event);
    }
}

impl TcgPcClientImrEvent {
    pub fn show(&self) {
        info!(
            "        --------------------Header Specification ID Event--------------------------"
        );
        info!("        IMR               : {}", self.imr_index);
        info!(
            "        Type              : {:02X?} ({})",
            self.event_type,
            &TcgEventType::get_event_type_string(self.event_type)
        );
        info!("        Digest:");
        dump_data(&self.digest.to_vec());
        info!("        Event:");
        dump_data(&self.event);
    }
}
