use hashbrown::HashMap;

pub const TPM_ALG_ERROR: u8 = 0x0;
pub const TPM_ALG_RSA: u8 = 0x1;
pub const TPM_ALG_SHA1: u8 = 0x4;
pub const TPM_ALG_SHA256: u8 = 0xB;
pub const TPM_ALG_SHA384: u8 = 0xC;
pub const TPM_ALG_SHA512: u8 = 0xD;
pub const TPM_ALG_ECDSA: u8 = 0x18;

// hash algorithm ID to algorithm name string map
lazy_static! {
    pub static ref ALGO_NAME_MAP: HashMap<u8, String> = {
        let mut map: HashMap<u8, String> = HashMap::new();
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
    fn get_algorithm_id(&self) -> u8;
}

// digest format: (algo id, hash value)
#[allow(dead_code)]
pub struct TcgDigest {
    algo_id: u8,
    hash: Vec<u8>,
}

// this trait retrieve IMR's max index of a CVM and hash value
pub trait TcgIMR {
    fn max_index(&self) -> u8;
    fn get_index(&self) -> u8;
    fn get_hash(&self) -> Vec<&str>;
    fn is_valid(&self) -> bool;
}
