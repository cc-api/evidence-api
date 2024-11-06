#![allow(non_camel_case_types)]
use crate::cc_type::*;
use hashbrown::HashMap;
use num_enum::TryFromPrimitive;

pub struct Tdx {}

// TDX version ID
#[derive(Clone, Eq, Hash, PartialEq)]
pub enum TdxVersion {
    TDX_1_0,
    TDX_1_5,
}

// TDX version ID to version string map
lazy_static! {
    pub static ref TDX_VERSION_MAP: HashMap<TdxVersion, String> = {
        let mut map: HashMap<TdxVersion, String> = HashMap::new();
        map.insert(TdxVersion::TDX_1_0, "1.0".to_string());
        map.insert(TdxVersion::TDX_1_5, "1.5".to_string());
        map
    };
}

// TDX version ID to device path string map
lazy_static! {
    pub static ref TDX_DEVICE_NODE_MAP: HashMap<TdxVersion, String> = {
        let mut map: HashMap<TdxVersion, String> = HashMap::new();
        map.insert(TdxVersion::TDX_1_0, TEE_TDX_1_0_PATH.to_string());
        map.insert(TdxVersion::TDX_1_5, TEE_TDX_1_5_PATH.to_string());
        map
    };
}

// quote and tdreport length
pub const REPORT_DATA_LEN: u32 = 64;
pub const TDX_REPORT_LEN: u32 = 1024;
pub const TDX_QUOTE_LEN: usize = 4 * 4096;

#[repr(u16)]
#[derive(Clone, PartialEq, Debug, TryFromPrimitive)]
pub enum AttestationKeyType {
    ECDSA_P256 = 2,
    ECDSA_P384 = 3,
}

#[repr(u32)]
#[derive(Clone, Debug, PartialEq, TryFromPrimitive)]
pub enum IntelTeeType {
    TEE_SGX = 0x00000000,
    TEE_TDX = 0x00000081,
}

macro_rules! impl_decode_for {
    ($type: ty) => {
        impl scale::Decode for $type {
            fn decode<In: scale::Input>(input: &mut In) -> Result<Self, scale::Error> {
                <Self as TryFromPrimitive>::Primitive::decode(input)?
                    .try_into()
                    .map_err(|_| {
                        let err_msg = concat!("failed to decode ", stringify!($type));
                        scale::Error::from(err_msg)
                    })
            }
        }
    };
}

impl_decode_for!(AttestationKeyType);
impl_decode_for!(IntelTeeType);

// QE_VENDOR_INTEL_SGX ID string "939a7233f79c4ca9940a0db3957f0607";
pub const QE_VENDOR_INTEL_SGX: [u8; 16] = [
    0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f, 0x06, 0x07,
];

#[derive(Clone, PartialEq, Debug)]
#[repr(i16)]
pub enum QeCertDataType {
    /*** QE Certification Data Type.
    Definition reference:
    https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf
    A.3.9. QE Certification Data - Version 4
    */
    PCK_ID_PLAIN = 1,
    PCK_ID_RSA_2048_OAEP = 2,
    PCK_ID_RSA_3072_OAEP = 3,
    PCK_LEAF_CERT_PLAIN = 4, // Currently not supported
    PCK_CERT_CHAIN = 5,
    QE_REPORT_CERT = 6,
    PLATFORM_MANIFEST = 7, // Currently not supported
}
pub const TDX_QUOTE_VERSION_4: u16 = 4;
pub const TDX_QUOTE_VERSION_5: u16 = 5;

pub const ACPI_TABLE_FILE_VM: &str = "/sys/firmware/acpi/tables/CCEL";
pub const ACPI_TABLE_DATA_FILE_VM: &str = "/sys/firmware/acpi/tables/data/CCEL";
pub const IMA_DATA_FILE_VM: &str = "/sys/kernel/security/integrity/ima/ascii_runtime_measurements";

pub const ACPI_TABLE_FILE_CONTAINER: &str = "/run/firmware/acpi/tables/CCEL";
pub const ACPI_TABLE_DATA_FILE_CONTAINER: &str = "/run/firmware/acpi/tables/data/CCEL";
pub const IMA_DATA_FILE_CONTAINER: &str =
    "/run/kernel/security/integrity/ima/ascii_runtime_measurements";
pub const ATTEST_CFG_FILE_PATH: &str = "/etc/tdx-attest.conf";
