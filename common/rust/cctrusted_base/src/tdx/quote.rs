#![allow(non_camel_case_types)]
use anyhow::anyhow;
use core::mem::transmute;
use core::result::Result;
use core::result::Result::Ok;
use log::*;

use crate::tdx::common::*;

#[repr(C)]
pub struct qgs_msg_header {
    pub major_version: u16, // TDX major version
    pub minor_version: u16, // TDX minor version
    pub msg_type: u32,      // GET_QUOTE_REQ or GET_QUOTE_RESP
    pub size: u32,          // size of the whole message, include this header, in byte
    pub error_code: u32,    // used in response only
}

#[repr(C)]
pub struct qgs_msg_get_quote_req {
    pub header: qgs_msg_header, // header.type = GET_QUOTE_REQ
    pub report_size: u32,       // cannot be 0
    pub id_list_size: u32,      // length of id_list, in byte, can be 0
    pub report_id_list: [u8; TDX_REPORT_LEN as usize], // report followed by id list
}

#[repr(C)]
pub struct tdx_quote_hdr {
    pub version: u64,                       // Quote version, filled by TD
    pub status: u64,                        // Status code of Quote request, filled by VMM
    pub in_len: u32,                        // Length of TDREPORT, filled by TD
    pub out_len: u32,                       // Length of Quote, filled by VMM
    pub data_len_be_bytes: [u8; 4], // big-endian 4 bytes indicate the size of data following
    pub data: [u8; TDX_QUOTE_LEN as usize], // Actual Quote data or TDREPORT on input
}

#[repr(C)]
pub struct tdx_quote_req {
    pub buf: u64, // Pass user data that includes TDREPORT as input. Upon successful completion of IOCTL, output is copied back to the same buffer
    pub len: u64, // Length of the Quote buffer
}

#[repr(C)]
pub struct qgs_msg_get_quote_resp {
    pub header: qgs_msg_header,        // header.type = GET_QUOTE_RESP
    pub selected_id_size: u32,         // can be 0 in case only one id is sent in request
    pub quote_size: u32,               // length of quote_data, in byte
    pub id_quote: [u8; TDX_QUOTE_LEN], // selected id followed by quote
}

impl Tdx {
    /***
        generate qgs message for TDX quote generation

        Args:
            report (Vec<u8>): tdreport

        Returns:
            qgs_msg_get_quote_req struct instance
    */
    pub fn generate_qgs_quote_msg(report: [u8; TDX_REPORT_LEN as usize]) -> qgs_msg_get_quote_req {
        //build quote service message header to be used by QGS
        let qgs_header = qgs_msg_header {
            major_version: 1,
            minor_version: 0,
            msg_type: 0,
            size: 16 + 8 + TDX_REPORT_LEN, // header + report_size and id_list_size + TDX_REPORT_LEN
            error_code: 0,
        };

        //build quote service message body to be used by QGS
        let mut qgs_request = qgs_msg_get_quote_req {
            header: qgs_header,
            report_size: TDX_REPORT_LEN,
            id_list_size: 0,
            report_id_list: [0; TDX_REPORT_LEN as usize],
        };

        qgs_request.report_id_list.copy_from_slice(&report[0..]);

        qgs_request
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct TdxQuoteHeader {
    /*** TD Quote Header.
    Attributes:
        ver: An integer version of the Quote data structure.
        ak_type: A ``AttestationKeyType`` indicating the type of the Attestation
                Key used by the Quoting Enclave.
        tee_type: A ``TeeType`` indicating the TEE for this attestation.
        reserved_1: Reserved 2 bytes.
        reserved_2: Reserved 2 bytes.
        qe_vendor: Bytes indicating the Unique identifier of the QE Vendor.
    Definition reference:
    https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf
    A.3.1. TD Quote Header
    Size is count in bytes:
    Name                    Size    Type        Description
    Version                 2       Integer     Version of the Quote data structure.
                                                    Value: 4
    Attestation Key Type    2       Integer     Type of the Attestation Key used by the
                                                Quoting Enclave. Supported values:
                                                        2 (ECDSA-256-with-P-256 curve)
                                                        3 (ECDSA-384-with-P-384 curve) (Note:
                                                            currently not supported)
                                                (Note: 0 and 1 are reserved, for when EPID is
                                                moved to version 4 quotes.)
    TEE Type                4       Integer     TEE for this Attestation
                                                    0x00000000: SGX
                                                    0x00000081: TDX
    RESERVED                2       Byte Array  Zero
    RESERVED                2       Byte Array  Zero
    QE Vendor ID            16      UUID        Unique identifier of the QE Vendor.
                                                    Value:
                                                    939A7233F79C4CA9940A0DB3957F0607
                                                    (Intel® SGX QE Vendor)
                                                Note: Each vendor that decides to provide a
                                                customized Quote data structure should have
                                                unique ID.
    User Data               20      Byte Array  Custom user-defined data. For the Intel® SGX
                                                and TDX DCAP Quote Generation Libraries, the
                                                first 16 bytes contain a Platform Identifier
                                                that is used to link a PCK Certificate to an
                                                Enc(PPID). This identifier is consistent for
                                                every quote generated with this QE on this
                                                platform
    */
    pub version: u16,
    pub ak_type: AttestationKeyType,
    pub tee_type: IntelTeeType,
    pub reserved_1: [u8; 2],
    pub reserved_2: [u8; 2],
    pub qe_vendor: [u8; 16],
    pub user_data: [u8; 20],
}

impl TdxQuoteHeader {
    pub fn show(&self) {
        info!("show the data of TdxQuoteHeader");
        info!("version = {}", self.version);
        info!("ak_type = {:?}", self.ak_type);
        info!("tee_type = {:?}", self.tee_type);
        info!("qe_vendor = {:02X?}", self.qe_vendor);
        info!("user_data = {:02X?}", self.user_data);
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct TdxQuoteBody {
    /*** TD Quote Body.
    We define TdxQuoteBody as the base class of Version 4 Quote Format and Version 5 Quote Format.
    Quote Format Version        Architecture    Class Usage Comment
    4                           TDX 1.0         TdxQuoteBody
    4                           TDX 1.5         TdxQuoteBody
    5                           TDX 1.0         TODO: should use TdxQuoteBody
    5                           TDX 1.5         TODO: should define a sub class with 2 more fields
                                                    TEE_TCB_SVN_2
                                                    MRSERVICETD
    5                           SGX             TODO: should define a new independent class
    Atrributes:
        data: A bytearray fo the raw data.
        tee_tcb_svn: describing the TCB of TDX.
        mrseam: A bytearray storing the Measurement of the TDX Module.
        mrsignerseam: A bytearray that should be zero for the Intel TDX Module.
        seamattributes: A bytearray storing SEAMATRIBUTES. Must be zero for TDX 1.0.
        tdattributes: A bytearray indicating TD Attributes.
        xfam: A bytearray storing XFAM (eXtended Features Available Mask).
        mrtd: A bytearray storing Measurement of the initial contents of the TD.
        mrconfig: A bytearray storing software-defined ID for non-owner-defined TD config.
        mrowner: A bytearray storing software-defined ID for the TD's owner.
        mrownerconfig: A bytearray storing software-defined ID for owner-defined TD config.
        rtmr0: A bytearray storing runtime extendable measurement register 0.
        rtmr1: A bytearray storing runtime extendable measurement register 1.
        rtmr2: A bytearray storing runtime extendable measurement register 2.
        rtmr3: A bytearray storing runtime extendable measurement register 3.
        reportdata: A bytearray storing 64 bytes custom data to a TD Report.
    Definition reference:
    https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf
    For Version 4 Quote Format, the TD Quote Body definition is used for both TDX 1.0 and TDX 1.5.
    A.3.2. TD Quote Body
    Name            Size (bytes)    Type            Description
    TEE_TCB_SVN     16              Byte Array      Describes the TCB of TDX.
    MRSEAM          48              SHA384          Measurement of the TDX Module.
    MRSIGNERSEAM    48              SHA384          Zero for the Intel® TDX Module.
    SEAMATTRIBUTES  8               Byte Array      Must be zero for TDX 1.0
    TDATTRIBUTES    8               Byte Array      TD Attributes
    XFAM            8               Byte Array      XFAM (eXtended Features Available Mask) is
                                                    defined as a 64b bitmap, which has the same
                                                    format as XCR0 or IA32_XSS MSR.
    MRTD            48              SHA384          Measurement of the initial contents of the TD.
                                                    See TDX Module definitions here: TDX Module
                                                    documentation
    MRCONFIGID      48              Byte Array      Software-defined ID for non-owner-defined
                                                    configuration of the TD, e.g., runtime or OS
                                                    configuration.
    MROWNER         48              Byte Array      Software-defined ID for the TD's owner
    MROWNERCONFIG   48              Byte Array      Software-defined ID for owner-defined
                                                    configuration of the TD, e.g., specific to the
                                                    workload rather than the runtime or OS.
    RTMR0           48              SHA384          Runtime extendable measurement register
    RTMR1           48              SHA384          Runtime extendable measurement register
    RTMR2           48              SHA384          Runtime extendable measurement register
    RTMR3           48              SHA384          Runtime extendable measurement register
    REPORTDATA      64              Byte Array      Each TD Quote is based on a TD Report. The
                                                    TD is free to provide 64 bytes of custom data
                                                    to a TD Report. For instance, this space can be
                                                    used to hold a nonce, a public key, or a hash
                                                    of a larger block of data.
                                                    Note that the signature of a TD Quote covers
                                                    the REPORTDATA field. As a result, the
                                                    integrity is protected with a key rooted in an
                                                    Intel CA.
    For Version 5 Quote Format, the TD Quote Body has 3 types:
    A.4.2. TD Quote Body Descriptor
    TD Quote Body Type architecturally supported values:
    - 1 (Future SGX support)
    - 2 (TD Quote Body for TDX 1.0)
    - 3 (TD Quote Body for TDX 1.5)
    For Version 5 Quote Format TD Quote Body, TDX 1.5 body has 2 more fields than TDX 1.0 in the
    trailling bytes:
    A.4.4. TD Quote Body for TDX 1.5
    Name            Size (bytes)    Type        Description
    TEE_TCB_SVN_2   16              Byte Array  Describes the current TCB of TDX. This value may
                                                will be different than TEE_TCB_SVN by loading a
                                                new version of the TDX Module using the TD
                                                Preserving update capability
    MRSERVICETD     48              SHA384      Measurement of the initial contents of the
                                                Migration TD
    */
    pub tee_tcb_svn: [u8; 16],    // Array of TEE TCB SVNs
    pub mrseam: [u8; 48],         // Measurement of the SEAM module (SHA384 hash)
    pub mrseam_signer: [u8; 48],  // Measurement of a 3rd party SEAM module’s signer (SHA384 hash)
    pub seam_attributes: [u8; 8], // ATTRIBUTES of SEAM
    pub td_attributes: [u8; 8],   // ATTRIBUTES of TD
    pub xfam: [u8; 8],            // XFAM of TD
    pub mrtd: [u8; 48],           // Measurement of the initial contents of the TD (SHA384 hash)
    pub mrconfigid: [u8; 48], // Software defined ID for non-owner-defined configuration of the TD
    pub mrowner: [u8; 48],    // Software defined ID for the guest TD’s owner
    pub mrownerconfig: [u8; 48], // Software defined ID for owner-defined configuration of the TD
    pub rtmr0: [u8; 48],      // data in RTMR0(SHA384 hash)
    pub rtmr1: [u8; 48],      // data in RTMR1(SHA384 hash)
    pub rtmr2: [u8; 48],      // data in RTMR2(SHA384 hash)
    pub rtmr3: [u8; 48],      // data in RTMR3(SHA384 hash)
    pub report_data: [u8; 64], // Additional Report Data
}

impl TdxQuoteBody {
    pub fn show(&self) {
        info!("show the data of TdxQuoteBody");
        info!("tee_tcb_svn = {:02X?}", self.tee_tcb_svn);
        info!("mrseam = {:02X?}", self.mrseam);
        info!("mrseam_signer = {:02X?}", self.mrseam_signer);
        info!("seam_attributes = {:02X?}", self.seam_attributes);
        info!("td_attributes = {:02X?}", self.td_attributes);
        info!("xfam = {:02X?}", self.xfam);
        info!("mrtd = {:02X?}", self.mrtd);
        info!("mrconfigid = {:02X?}", self.mrconfigid);
        info!("mrowner = {:02X?}", self.mrowner);
        info!("mrownerconfig = {:02X?}", self.mrownerconfig);
        info!("rtmr0 = {:02X?}", self.rtmr0);
        info!("rtmr1 = {:02X?}", self.rtmr1);
        info!("rtmr2 = {:02X?}", self.rtmr2);
        info!("rtmr3 = {:02X?}", self.rtmr3);
        info!("report_data = {:02X?}", self.report_data);
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct TdxEnclaveReportBody {
    pub cpu_svn: [u8; 16],
    pub miscselect: [u8; 4],
    pub reserved_1: [u8; 28],
    pub attributes: [u8; 16],
    pub mrenclave: [u8; 32],
    pub reserved_2: [u8; 32],
    pub mrsigner: [u8; 32],
    pub reserved_3: [u8; 96],
    pub isv_prodid: i16,
    pub isv_svn: i16,
    pub reserved_4: [u8; 60],
    pub report_data: [u8; 64],
}

impl TdxEnclaveReportBody {
    pub fn show(&self) {
        info!("show the data of TdxEnclaveReportBody");
        info!("cpu_svn = {:02X?}", self.cpu_svn);
        info!("miscselect = {:02X?}", self.miscselect);
        info!("attributes = {:02X?}", self.attributes);
        info!("mrenclave = {:02X?}", self.mrenclave);
        info!("mrsigner = {:02X?}", self.mrsigner);
        info!("isv_prodid = {:02X?}", self.isv_prodid);
        info!("isv_svn = {:02X?}", self.isv_svn);
        info!("report_data = {:02X?}", self.report_data);
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct TdxQuoteQeReportCert {
    /*** TD Quote QE Report Certification Data.
    Atrributes:
        qe_report: A bytearray storing the SGX Report of the Quoting Enclave that
                   generated an Attestation Key.
        qe_report_sig: A bytearray storing ECDSA signature over the QE Report
                       calculated using the Provisioning Certification Key (PCK).
        qe_auth_cert: A bytearray storing the QE Authentication Data and QE
                      Certification Data.
    Definition reference:
    https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf
    A.3.11. QE Report Certification Data
    */
    pub qe_report: TdxEnclaveReportBody,
    pub qe_report_sig: [u8; 64],
    pub qe_auth_data: Vec<u8>,
    pub qe_auth_cert: Box<TdxQuoteQeCert>,
}

impl TdxQuoteQeReportCert {
    pub fn new(data: Vec<u8>) -> TdxQuoteQeReportCert {
        let tdx_enclave_report_body: TdxEnclaveReportBody = unsafe {
            transmute::<[u8; 384], TdxEnclaveReportBody>(
                data[0..384]
                    .try_into()
                    .expect("slice with incorrect length"),
            )
        };
        let qe_report_sig = data[384..448].try_into().unwrap();
        let auth_data_size = unsafe {
            transmute::<[u8; 2], u16>(
                data[448..450]
                    .try_into()
                    .expect("slice with incorrect length"),
            )
        }
        .to_le();
        let auth_data_end = 450 + auth_data_size;
        let mut qe_auth_data = Vec::new();
        if auth_data_size > 0 {
            qe_auth_data = data[450..auth_data_end as usize].to_vec();
        }

        TdxQuoteQeReportCert {
            qe_report: tdx_enclave_report_body,
            qe_report_sig,
            qe_auth_data,
            qe_auth_cert: Box::new(TdxQuoteQeCert::new(data[auth_data_end as usize..].to_vec())),
        }
    }

    pub fn show(&self) {
        info!("show the data of TdxQuoteQeReportCert");
        self.qe_report.show();
        info!("qe_report_sig = {:02X?}", self.qe_report_sig);
        info!("qe_auth_data = {:02X?}", self.qe_auth_data);
        self.qe_auth_cert.show();
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct TdxQuoteQeCert {
    /*** TD Quote QE Certification Data.
    Attributes:
        cert_type: A ``QeCertDataType`` determining the type of data required to verify the
                   QE Report Signature in the Quote Signature Data structure.
        cert_data: A ``TdxQuoteQeReportCert`` storing the data required to verify the QE
                   Report Signature depending on the value of the Certification Data Type.
    Definition reference:
    https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf
    A.3.9. QE Certification Data - Version 4
    */
    pub cert_type: QeCertDataType,
    pub cert_data_struct: Option<Box<TdxQuoteQeReportCert>>,
    pub cert_data_vec: Option<Vec<u8>>,
}

impl TdxQuoteQeCert {
    pub fn new(data: Vec<u8>) -> TdxQuoteQeCert {
        let cert_type: QeCertDataType = unsafe {
            transmute::<[u8; 2], QeCertDataType>(
                data[0..2].try_into().expect("slice with incorrect length"),
            )
        };
        let cert_size = unsafe {
            transmute::<[u8; 4], u32>(data[2..6].try_into().expect("slice with incorrect length"))
        }
        .to_le();
        let cert_data_end = 6 + cert_size;

        if cert_type == QeCertDataType::QE_REPORT_CERT {
            let cert_data = TdxQuoteQeReportCert::new(data[6..cert_data_end as usize].to_vec());
            TdxQuoteQeCert {
                cert_type: cert_type as QeCertDataType,
                cert_data_struct: Some(Box::new(cert_data)),
                cert_data_vec: None,
            }
        } else {
            let cert_data = data[6..cert_data_end as usize].to_vec();
            TdxQuoteQeCert {
                cert_type: cert_type as QeCertDataType,
                cert_data_struct: None,
                cert_data_vec: Some(cert_data),
            }
        }
    }

    pub fn show(&self) {
        info!("show the data of TdxQuoteQeCert");
        info!("cert_type = {:?}", self.cert_type);
        match &self.cert_data_struct {
            None => match &self.cert_data_vec {
                None => (),
                Some(cert_data_vec) => info!("cert_data_vec = {:2X?}", cert_data_vec),
            },
            Some(cert_data_struct) => cert_data_struct.show(),
        }
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct TdxQuoteEcdsa256Sigature {
    /*** TD Quote ECDSA 256-bit Quote Signature.
    Atrributes:
        sig: A bytearray storing ECDSA signature over the Header and the TD
             Quote Body calculated using the private part of the
             Attestation Key generated by the Quoting Enclave.
        ak: A bytearray storing Public part of the Attestation Key generated
            by the Quoting Enclave.
        qe_cert: A ``TdxQuoteQeCert`` storing the data required to verify
                 the signature over QE Report and the Attestation Key.
    Definition reference:
    https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf
    A.3.8
    */
    pub sig: [u8; 64],
    pub ak: [u8; 64],
    pub qe_cert: TdxQuoteQeCert,
}

impl TdxQuoteEcdsa256Sigature {
    pub fn new(data: Vec<u8>) -> TdxQuoteEcdsa256Sigature {
        let sig = data[0..64].try_into().unwrap();
        let ak = data[64..128].try_into().unwrap();
        let qe_cert = TdxQuoteQeCert::new(data[128..data.len()].to_vec());

        TdxQuoteEcdsa256Sigature { sig, ak, qe_cert }
    }

    pub fn show(&self) {
        info!("show the data of TdxQuoteEcdsa256Sigature");
        info!("sig = {:02X?}", self.sig);
        info!("ak = {:02X?}", self.ak);
        self.qe_cert.show();
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct TdxQuoteSignature {
    pub data: Vec<u8>,
}

#[derive(Clone)]
pub struct TdxQuote {
    /*** TDX Quote.
    Atrributes:
        header: A ``TdxQuoteHeader`` storing the data of Quote Header.
        body: A ``TdxQuoteBody`` storing the data of TD Quote body.
        sig: Quote Signature. Currently only support ``TdxQuoteEcdsa256Sigature``.
    Definition reference:
    https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf
    A.3. Version 4 Quote Format (TDX-ECDSA, SGX-ECDSA, and SGX-EPID)
    Endianess: Little Endian (applies to all integer fields). Size in bytes:
    Name            Size    Type            Description
    Quote Header    48      TD Quote Header Header of Quote data structure.
                                            This field is transparent, i.e., the user knows its
                                            internal structure.
                                            Rest of the Quote data structure can be treated as
                                            opaque, i.e., hidden from the user.
    TD Quote Body   584     TD Quote Body   Report of the attested TD.
                                            The REPORTDATA contained in this field is defined
                                            by the TD developer. See the description of the
                                            field for example usages.
    Quote Signature 4       Integer         Size of the Quote Signature Data structure
    Data Len
    Quote Signature Variable Signature      Variable-length data containing the signature and
    Data                     Dependent      supporting data. For instance, an ECDSA P-256
                                            Signature
    For Version 5
    TODO: implement version 5 according to A.4. Version 5 Quote Format.
    */
    pub header: TdxQuoteHeader,
    pub body: TdxQuoteBody,
    pub tdx_quote_ecdsa256_sigature: Option<TdxQuoteEcdsa256Sigature>, // for AttestationKeyType.ECDSA_P256
    pub tdx_quote_signature: Option<TdxQuoteSignature>, // for AttestationKeyType.ECDSA_P384
}

impl TdxQuote {
    pub fn parse_tdx_quote(quote: Vec<u8>) -> Result<TdxQuote, anyhow::Error> {
        let tdx_quote_header: TdxQuoteHeader = unsafe {
            transmute::<[u8; 48], TdxQuoteHeader>(
                quote[0..48]
                    .try_into()
                    .expect("slice with incorrect length"),
            )
        };
        if tdx_quote_header.version == TDX_QUOTE_VERSION_4 {
            let tdx_quote_body: TdxQuoteBody = unsafe {
                transmute::<[u8; 584], TdxQuoteBody>(
                    quote[48..632]
                        .try_into()
                        .expect("slice with incorrect length"),
                )
            };
            let sig_len = unsafe {
                transmute::<[u8; 4], i32>(
                    quote[632..636]
                        .try_into()
                        .expect("slice with incorrect length"),
                )
            }
            .to_le();
            let sig_idx_end = 636 + sig_len;

            if tdx_quote_header.ak_type == AttestationKeyType::ECDSA_P256 {
                let tdx_quote_ecdsa256_sigature =
                    TdxQuoteEcdsa256Sigature::new(quote[636..sig_idx_end as usize].to_vec());

                Ok(TdxQuote {
                    header: tdx_quote_header,
                    body: tdx_quote_body,
                    tdx_quote_signature: None,
                    tdx_quote_ecdsa256_sigature: Some(tdx_quote_ecdsa256_sigature),
                })
            } else if tdx_quote_header.ak_type == AttestationKeyType::ECDSA_P384 {
                let tdx_quote_signature = TdxQuoteSignature {
                    data: quote[636..sig_idx_end as usize].to_vec(),
                };

                Ok(TdxQuote {
                    header: tdx_quote_header,
                    body: tdx_quote_body,
                    tdx_quote_signature: Some(tdx_quote_signature),
                    tdx_quote_ecdsa256_sigature: None,
                })
            } else {
                return Err(anyhow!("[parse_tdx_quote] unknown ak_type!"));
            }
        } else if tdx_quote_header.version == TDX_QUOTE_VERSION_5 {
            // TODO: implement version 5
            todo!()
        } else {
            return Err(anyhow!(
                "[parse_tdx_quote] unknown quote header version: {:}",
                tdx_quote_header.version
            ));
        }
    }
}
