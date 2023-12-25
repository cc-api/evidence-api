use crate::cc_type::CcType;
use crate::tcg::TcgDigest;

// holds the device node info
pub struct DeviceNode {
    pub device_path: String,
}

pub struct CcEventlogs {
    //TODO
}

// the interfaces a TEE should implement
pub trait TEE {
    /***
        retrive TEE signed report

        Args:
            nonce (String): against replay attacks
            data (String): user data

        Returns:
            the cc report byte array or error information
    */
    fn process_cc_report(&mut self, nonce: String, data: String) -> Result<Vec<u8>, anyhow::Error>;

    /***
        retrive TEE measurement registers, e.g.: RTMRs, vTPM PCRs, etc.

        Args:
            index (u8): the index of measurement register,
            algo_id (u8): the alrogithms ID

        Returns:
            TcgDigest struct
    */
    fn process_cc_measurement(&self, _index: u8, _algo_id: u8) -> TcgDigest;

    //TODO!
    fn process_cc_eventlog(&self);

    fn get_cc_type(&self) -> CcType;

    //Dump confidential TEE information
    fn dump(&self);
}
