use crate::tdvm::TdxVM;
use anyhow::*;
use cctrusted_base::cc_type::*;
use cctrusted_base::tcg::EventLogEntry;
use cctrusted_base::tcg::{TcgAlgorithmRegistry, TcgDigest};
use std::path::Path;

// the interfaces a CVM should implement
pub trait CVM {
    /***
        retrive CVM signed report

        Args:
            nonce (String): against replay attacks
            data (String): user data

        Returns:
            the cc report byte array or error information
    */
    fn process_cc_report(
        &mut self,
        nonce: Option<String>,
        data: Option<String>,
    ) -> Result<Vec<u8>, anyhow::Error>;

    /***
        retrive CVM max number of measurement registers

        Args:
            None

        Returns:
            max index of register of CVM
    */
    fn get_max_index(&self) -> u8;

    /***
        retrive CVM measurement registers, e.g.: RTMRs, vTPM PCRs, etc.

        Args:
            index (u8): the index of measurement register,
            algo_id (u8): the alrogithms ID

        Returns:
            TcgDigest struct
    */
    fn process_cc_measurement(&self, index: u8, algo_id: u16) -> Result<TcgDigest, anyhow::Error>;

    /***
        retrive CVM eventlogs

        Args:
            start and count of eventlogs

        Returns:
            array of eventlogs
    */
    fn process_cc_eventlog(
        &self,
        start: Option<u32>,
        count: Option<u32>,
    ) -> Result<Vec<EventLogEntry>, anyhow::Error>;

    /***
        retrive CVM type

        Args:
            None

        Returns:
            CcType of CVM
    */
    fn get_cc_type(&self) -> CcType;

    //Dump confidential CVM information
    fn dump(&self);
}

// used for return of Boxed trait object in build_cvm()
// this composed trait includes functions in both trait CVM and trait TcgAlgorithmRegistry
pub trait BuildCVM: CVM + TcgAlgorithmRegistry {}

// holds the device node info
pub struct DeviceNode {
    pub device_path: String,
}

/***
 instance a specific  object containers specific CVM methods
 and desired trait functions specified by "dyn BuildCVM"
*/
pub fn build_cvm() -> Result<Box<dyn BuildCVM>, anyhow::Error> {
    // instance a CVM according to detected TEE type
    match get_cvm_type().tee_type {
        TeeType::TDX => Ok(Box::new(TdxVM::new())),
        TeeType::SEV => todo!(),
        TeeType::CCA => todo!(),
        TeeType::TPM => todo!(),
        TeeType::PLAIN => Err(anyhow!("[build_cvm] Error: not in any TEE!")),
    }
}

// detect CVM type
pub fn get_cvm_type() -> CcType {
    let mut tee_type = TeeType::PLAIN;
    if Path::new(TEE_TPM_PATH).exists() {
        tee_type = TeeType::TPM;
    } else if Path::new(TEE_TDX_1_0_PATH).exists() || Path::new(TEE_TDX_1_5_PATH).exists() {
        tee_type = TeeType::TDX;
    } else if Path::new(TEE_SEV_PATH).exists() {
        tee_type = TeeType::SEV;
    } else {
        // TODO add support for CCA and etc.
    }

    CcType {
        tee_type: tee_type.clone(),
        tee_type_str: TEE_NAME_MAP.get(&tee_type).unwrap().to_owned(),
    }
}
