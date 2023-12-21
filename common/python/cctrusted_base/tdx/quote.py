"""
TDX Quote Related Classes
"""

from abc import ABC, abstractmethod
import ctypes
import logging
import struct

from enum import Enum
from cctrusted_base.binaryblob import BinaryBlob
from cctrusted_base.quote import Quote, QuoteData, QuoteSignature
from cctrusted_base.tdx.common import TDX_QUOTE_VERSION_4, TDX_QUOTE_VERSION_5
from cctrusted_base.tdx.common import TDX_VERSION_1_0, TDX_VERSION_1_5

LOG = logging.getLogger(__name__)

DUMP_FORMAT_RAW = "raw"
DUMP_FORMAT_HUMAN = "human"

def info(s: str):
    """
    Local wrapper function to log information
    """
    LOG.info(s)

class AttestationKeyType(Enum):
    """
    Attestation Key Type
    """
    ECDSA_P256 = 2
    ECDSA_P384 = 3

class TeeType(Enum):
    """
    TEE Type
    """
    TEE_SGX = 0x00000000
    TEE_TDX = 0x00000081

QE_VENDOR_INTEL_SGX = "939a7233f79c4ca9940a0db3957f0607"
"""
QE Vendor ID. Unique identifier of the QE Vendor.
e.g. Value: 939A7233F79C4CA9940A0DB3957F0607 (Intel® SGX QE Vendor)
Note: Each vendor that decides to provide a customized Quote data structure should have
unique ID.
"""

class QeCertDataType(Enum):
    """
    QE Certification Data Type
    Definition reference:
    https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/TDX_Quoting_Library_API.pdf
    A.3.9. QE Certification Data - Version 4
    """
    PCK_ID_PLAIN            = 1
    PCK_ID_RSA_2048_OAEP    = 2
    PCK_ID_RSA_3072_OAEP    = 3
    PCK_LEAF_CERT_PLAIN     = 4 # Currently not supported
    PCK_CERT_CHAIN          = 5
    QE_REPORT_CERT          = 6
    PLATFORM_MANIFEST       = 7 # Currently not supported

class TdxQuoteHeader(BinaryBlob):
    """
    Quote Header
    Definition reference:
    https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/TDX_Quoting_Library_API.pdf
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
    """

    def __init__(self, data: bytearray):
        """
        Init function does 2 things:
            1. Save raw data in its super property.
            2. Parse the raw data and save each field as the properties of its "self".
        """
        super().__init__(data)
        v = memoryview(self.data)
        self.ver = int.from_bytes(v[0:2].tobytes(), "little")
        self.ak_type = AttestationKeyType(int.from_bytes(v[2:4].tobytes(), "little"))
        self.tee_type = TeeType(int.from_bytes(v[4:8].tobytes(), "little"))
        self.reserved_1 = v[8:10].tobytes()
        self.reserved_2 = v[10:12].tobytes()
        self.qe_vendor = v[12:28].tobytes()

    def dump(self, fmt=DUMP_FORMAT_RAW, indent=""):
        """
        Dump data. Default format is raw.
        """
        info(f'{indent}TD Quote Header:')
        if fmt == DUMP_FORMAT_HUMAN:
            i = indent + "  "
            info(f'{i}Header Version: {self.ver}')
            info(f'{i}Attestation Key Type: {self.ak_type}')
            info(f'{i}TEE Type: {self.tee_type}')
            info(f'{i}Reserved 1: {self.reserved_1.hex()}')
            info(f'{i}Reserved 2: {self.reserved_2.hex()}')
            qe_vendor_name = ""
            if QE_VENDOR_INTEL_SGX == self.qe_vendor.hex():
                # This is the only defined QE Vendor so far according to the spec
                # The link to the spec is given in the docstring of TdxQuoteHeader.
                qe_vendor_name = " # Intel® SGX QE Vendor"
            info(f'{i}QE Vendor ID: {self.qe_vendor.hex()}{qe_vendor_name}')
        else:
            # Default output raw data in hex string
            super().dump()

class TdxQuoteTeeTcbSvn(BinaryBlob):
    """
    TEE TCB SVN structure in TD Quote Body
    Definition reference:
    https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/TDX_Quoting_Library_API.pdf
    A.3.3. TEE_TCB_SVN
    """

    def __init__(self, data: bytearray):
        super().__init__(data)

    def dump(self, fmt=DUMP_FORMAT_RAW, indent=""):
        """
        Dump data. Default format is raw.
        """
        info(f'{indent}{type(self).__name__}:')
        if fmt == DUMP_FORMAT_HUMAN:
            i = indent + "  "
            info(f'{i}tdxtcbcomp01: {self.data[0]}')
            info(f'{i}tdxtcbcomp02: {self.data[1]}')
            info(f'{i}tdxtcbcomp03: {self.data[2]}')
            info(f'{i}tdxtcbcomp04: {self.data[3]}')
            info(f'{i}tdxtcbcomp05: {self.data[4]}')
            info(f'{i}tdxtcbcomp06: {self.data[5]}')
            info(f'{i}tdxtcbcomp07: {self.data[6]}')
            info(f'{i}tdxtcbcomp08: {self.data[7]}')
            info(f'{i}tdxtcbcomp09: {self.data[8]}')
            info(f'{i}tdxtcbcomp10: {self.data[9]}')
            info(f'{i}tdxtcbcomp11: {self.data[10]}')
            info(f'{i}tdxtcbcomp12: {self.data[11]}')
            info(f'{i}tdxtcbcomp13: {self.data[12]}')
            info(f'{i}tdxtcbcomp14: {self.data[13]}')
            info(f'{i}tdxtcbcomp15: {self.data[14]}')
            info(f'{i}tdxtcbcomp16: {self.data[15]}')
        else:
            # Default output raw data in hex string
            super().dump()

class TdxQuoteBody(BinaryBlob):
    """
    Quote Body for TDX.
    We define TdxQuoteBody as the base class of Version 4 Quote Format and Version 5 Quote Format.
    Quote Format Version        Architecture    Class Usage Comment
    4                           TDX 1.0         TdxQuoteBody
    4                           TDX 1.5         TdxQuoteBody
    5                           TDX 1.0         TODO: should use TdxQuoteBody
    5                           TDX 1.5         TODO: should define a sub class with 2 more fields
                                                    TEE_TCB_SVN_2
                                                    MRSERVICETD
    5                           SGX             TODO: should define a new independent class

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
    """

    def __init__(self, data: bytearray):
        """
        Init function does 2 things:
            1. Save raw data in its super property.
            2. Parse the raw data and save each field as the properties of its "self".
        """
        super().__init__(data)
        v = memoryview(self.data)
        self.tee_tcb_svn = TdxQuoteTeeTcbSvn(v[0:16].tobytes())
        self.mrseam = v[16:64].tobytes()
        self.mrsignerseam = v[64:112].tobytes()
        self.seamattributes = v[112:120].tobytes()
        self.tdattributes = v[120:128].tobytes()
        self.xfam = v[128:136].tobytes()
        self.mrtd = v[136:184].tobytes()
        self.mrconfig = v[184:232].tobytes()
        self.mrowner = v[232:280].tobytes()
        self.mrownerconfig = v[280:328].tobytes()
        self.rtmr0 = v[328:376].tobytes()
        self.rtmr1 = v[376:424].tobytes()
        self.rtmr2 = v[424:472].tobytes()
        self.rtmr3 = v[472:520].tobytes()
        self.reportdata = v[520:584].tobytes()

    def dump(self, fmt=DUMP_FORMAT_RAW, indent=""):
        """
        Dump data. Default format is raw.
        """
        info(f'{indent}TD Quote Body:')
        if fmt == DUMP_FORMAT_HUMAN:
            i = indent + "  "
            self.tee_tcb_svn.dump(fmt, i)
            info(f'{i}MRSEAM: 0x{self.mrseam.hex()}')
            info(f'{i}MRSIGNERSEAM: 0x{self.mrsignerseam.hex()}')
            info(f'{i}SEAMATTRIBUTES: 0x{self.seamattributes.hex()}')
            info(f'{i}TDATTRIBUTES: 0x{self.tdattributes.hex()}')
            info(f'{i}XFAM: 0x{self.xfam.hex()}')
            info(f'{i}MRTD: 0x{self.mrtd.hex()}')
            info(f'{i}MRCONFIG: 0x{self.mrconfig.hex()}')
            info(f'{i}MROWNER: 0x{self.mrowner.hex()}')
            info(f'{i}MROWNERCONFIG: 0x{self.mrownerconfig.hex()}')
            info(f'{i}RTMR0: 0x{self.rtmr0.hex()}')
            info(f'{i}RTMR1: 0x{self.rtmr1.hex()}')
            info(f'{i}RTMR2: 0x{self.rtmr2.hex()}')
            info(f'{i}RTMR3: 0x{self.rtmr3.hex()}')
            info(f'{i}REPORTDATA: 0x{self.reportdata.hex()}')
        else:
            super().dump()

class TdxQuoteQeReportCert(BinaryBlob):
    """
    TDX Quote QE Report Certification Data
    Definition reference:
    https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/TDX_Quoting_Library_API.pdf
    A.3.11. QE Report Certification Data
    """

    def __init__(self, data: bytearray):
        super().__init__(data)
        v = memoryview(self.data)
        self.qe_report = v[0:384].tobytes()
        self.qe_report_sig = v[384:448].tobytes()
        self.qe_auth_cert = v[448:].tobytes()

    def dump(self, fmt=DUMP_FORMAT_RAW, indent=""):
        """
        Dump data. Default format is raw.
        """
        info(f'{indent}{type(self).__name__}:')
        if fmt == DUMP_FORMAT_HUMAN:
            i = indent + "  "
            info(f'{i}Quote QE Report: 0x{self.qe_report.hex()}')
            info(f'{i}Quote QE Report Signature: 0x{self.qe_report_sig.hex()}')
            info(f'{i}Quote QE Authentication & Cert Data: {self.qe_auth_cert.decode("utf-8")}')
        else:
            # Default output raw data in hex string
            super().dump()

class TdxQuoteQeCert(BinaryBlob):
    """
    TDX Quote QE Certification Data
    Definition reference:
    https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/TDX_Quoting_Library_API.pdf
    A.3.9. QE Certification Data - Version 4
    """

    def __init__(self, data: bytearray):
        super().__init__(data)
        v = memoryview(self.data)
        self.cert_type = QeCertDataType(int.from_bytes(v[0:2].tobytes(), "little"))
        self.cert_size = int.from_bytes(v[2:6].tobytes(), "little")
        cert_data_end = 6 + self.cert_size
        if self.cert_type == QeCertDataType.QE_REPORT_CERT:
            self.cert_data = TdxQuoteQeReportCert(v[6:cert_data_end].tobytes())
        else:
            self.cert_data = v[6:cert_data_end].tobytes()

    def dump(self, fmt=DUMP_FORMAT_RAW, indent=""):
        """
        Dump data. Default format is raw.
        """
        info(f'{indent}{type(self).__name__}:')
        if fmt == DUMP_FORMAT_HUMAN:
            i = indent + "  "
            info(f'{i}Quote QE Cert Data Type: {self.cert_type}')
            info(f'{i}Quote QE Cert Data Size: {self.cert_size}')
            if self.cert_type == QeCertDataType.QE_REPORT_CERT:
                self.cert_data.dump(fmt, i)
            else:
                info(f'{i}Quote QE Cert Data: {self.cert_data}')
        else:
            # Default output raw data in hex string
            super().dump()

class TdxQuoteEcdsa256Sigature(QuoteSignature):
    """
    TDX Quote ECDSA 256-bit Quote Signature
    Definition reference:
    https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/TDX_Quoting_Library_API.pdf
    A.3.8. ECDSA 256-bit Quote Signature Data Structure - Version 4
    """

    def __init__(self, data: bytearray):
        super().__init__(data)
        v = memoryview(self.data)
        self.sig = v[0:64].tobytes()
        self.ak = v[64:128].tobytes()
        self.qe_cert = TdxQuoteQeCert(v[128:].tobytes())

    def dump(self, fmt=DUMP_FORMAT_RAW, indent=""):
        """
        Dump data. Default format is raw.
        """
        info(f'{indent}TD Quote Signature:')
        if fmt == DUMP_FORMAT_HUMAN:
            i = indent + "  "
            info(f'{i}Quote Signature (ECDSA P-256 Signature): 0x{self.sig.hex()}')
            info(f'{i}ECDSA Attestation Key (ECDSA P-256 Public Key): 0x{self.ak.hex()}')
            self.qe_cert.dump(fmt, i)
        else:
            # Default output raw data in hex string
            super().dump()

class TdxQuoteSignature(QuoteSignature):
    """
    TDX Quote Signature
    """

    def __init__(self, data: bytearray):
        super().__init__(data)

    def dump(self, fmt=DUMP_FORMAT_RAW, indent=""):
        """
        Dump data. Default format is raw.
        """
        info(f'{indent}TD Quote Signature:')
        if fmt == DUMP_FORMAT_HUMAN:
            info("")
        else:
            super().dump()

class TdxQuote(Quote):
    """
    TDX Quote
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
    """

    def __init__(self, data: bytearray):
        super().__init__(data)
        v = memoryview(self.data)
        self.header = TdxQuoteHeader(v[0:48].tobytes())
        version = self.header.ver
        if version == TDX_QUOTE_VERSION_4:
            self.body = TdxQuoteBody(v[48:632].tobytes())
            sig_len = int.from_bytes(v[632:636].tobytes(), "little")
            sig_idx_end = 636 + sig_len
            if self.header.ak_type == AttestationKeyType.ECDSA_P256:
                self.sig = TdxQuoteEcdsa256Sigature(v[636:sig_idx_end].tobytes())
            else:
                self.sig = TdxQuoteSignature(v[636:sig_idx_end].tobytes())
        elif version == TDX_QUOTE_VERSION_5:
            # TODO: implement version 5
            # For Version 5, it defines "A.4.2. TD Quote Body Descriptor" that embedded
            # the body data. We can parse the body data from that Body Descriptor and
            # store it as a property of this class.
            info("TODO: TD Quote Version 5 will be implemented later!")
        else:
            info(f'TD Quote Version {self.header.ver} is not supported!')

    def get_quoted_data(self) -> QuoteData:
        """
        Get TD Quoted Data
        """
        return self.body

    def get_sig(self) -> QuoteSignature:
        """
        Get TD Quote signature
        """
        return self.sig

    def dump(self, is_raw=True) -> None:
        """
        Dump Quote Data.

        Args:
            is_raw:
                True: dump in hex strings
                False: dump in human readable texts
        Returns:
            None
        Raises:
            None
        """
        info("======================================")
        info("TD Quote")
        info("======================================")
        out_format = DUMP_FORMAT_RAW
        if is_raw is not True:
            out_format = DUMP_FORMAT_HUMAN
        if self.header is not None:
            self.header.dump(fmt=out_format)
        if self.body is not None:
            self.body.dump(fmt=out_format)
        if self.sig is not None:
            self.sig.dump(fmt=out_format)

class TdxQuoteReq(ABC):

    def __init__(self, ver):
        self._version = ver

    @property
    def version(self):
        """
        The TDX version
        """
        return self._version

    @abstractmethod
    def prepare_reqbuf(self, report_data=None) -> bytearray:
        """
        Return the request data for TD Quote
        """
        raise NotImplementedError("Should be implemented by inherited class")

    @abstractmethod
    def process_output(self, rawdata) -> TdxQuote:
        """
        Process response data from IOCTL
        """
        raise NotImplementedError("Should be implemented by inherited class")

class TdxQuoteReq10(TdxQuoteReq):

    def __init__(self):
        TdxQuoteReq.__init__(self, TDX_VERSION_1_0)

    def prepare_reqbuf(self, report_data=None) -> bytearray:
        assert False, "Need implement later"

    def process_output(self, rawdata) -> TdxQuote:
        assert False, "Need implement later"

class TdxQuoteReq15(TdxQuoteReq):

    # The length of the tdquote 4 pages
    TDX_QUOTE_LEN = 4 * 4096

    def __init__(self):
        TdxQuoteReq.__init__(self, TDX_VERSION_1_5)
        self.tdquote = None

    def qgs_msg_quote_req(self, tdreport):
        '''
        Method qgs_msg_quote_req generates QGS messages for tdquote
        Refer: https://github.com/intel/SGXDataCenterAttestationPrimitives
        qgs_msg_header_t & qgs_msg_get_quote_req_t
        uint16_t major_version = 1;
        uint16_t minor_version = 0;
        uint32_t type = 0 (GET_QUOTE_REQ);
        // size of the whole message, include this header, in byte
        uint32_t size = header + report_size + id_list_size;
        uint32_t error_code = 0; // used in response only

        uint32_t report_size = report_size; // cannot be 0
        uint32_t id_list_size = 0; // length of id_list, in byte, can be 0
        uint8_t report_id_list[] = NULL;
        '''
        major_version = 1
        minor_version = 0
        msg_type = 0
        error_code = 0
        msg_size = 0
        report_size = 0
        id_list_size = 0

        if tdreport is not None:
            report_size = len(tdreport)
        # sizeof(qgs_msg_get_quote_req_t)
        msg_size = 16 + 8 + report_size

        qgs_msg = struct.pack(f"2H5I{report_size}s", major_version, minor_version, msg_type,
                    msg_size, error_code, report_size, id_list_size, tdreport)
        return qgs_msg

    def prepare_reqbuf(self, report_data=None) -> bytearray:
        '''
        Method prepare_reqbuf creates a tdx_quote_req struct
        with report_data. Refer TDX Guest Hypervisor Communication
        Interface (GHCI) specification.
        struct tdx_quote_hdr {
            /* Quote version, filled by TD */
            __u64 version;
            /* Status code of Quote request, filled by VMM */
            __u64 status;
            /* Length of TDREPORT, filled by TD */
            __u32 in_len;
            /* Length of Quote, filled by VMM */
            __u32 out_len;
            /* Actual Quote data or TDREPORT on input */
            __u64 data[0];
        };
        https://cdrdv2.intel.com/v1/dl/getContent/726792
        Intel TDX Guest-Hypervisor Communication Interface v1.5
        '''
        report_size = len(report_data)
        version = 1
        status = 0
        in_len = 0
        out_len = 0

        qgs_msg = self.qgs_msg_quote_req(report_data)
        in_len = len(qgs_msg) + 4

        tdquote_hdr = struct.pack(f"QQII4s{report_size}s", version, status, in_len, out_len,
            len(qgs_msg).to_bytes(4, "big"), qgs_msg)
        self.tdquote = ctypes.create_string_buffer(TdxQuoteReq15.TDX_QUOTE_LEN)
        self.tdquote[:len(tdquote_hdr)] = tdquote_hdr
        reqbuf = struct.pack("QQ", ctypes.addressof(self.tdquote), TdxQuoteReq15.TDX_QUOTE_LEN)
        return reqbuf

    def qgs_msg_quote_resp(self, buf):
        '''
        Method qgs_msg_quote_resp parse tdquote from the response of QGS
        Refer: https://github.com/intel/SGXDataCenterAttestationPrimitives
        qgs_msg_header_t & qgs_msg_get_quote_resp_t
        uint16_t major_version = 1;
        uint16_t minor_version = 0;
        uint32_t type = 1 (GET_QUOTE_RESP);
        uint32_t size = header + quote;
        uint32_t error_code = 0; // used in response only

        uint32_t selected_id_size;  // can be 0 in case only one id is sent in request
        uint32_t quote_size;        // length of quote_data, in byte
        uint8_t id_quote[];         // selected id followed by quote
        '''
        msg_size = len(buf) - (16 + 8)
        major_version, minor_version, msg_type, msg_size, error_code, _, quote_size, quote = \
            struct.unpack(f"2H5I{msg_size}s", buf)
        if major_version != 1 and minor_version != 0 and msg_type != 1 and error_code != 0:
            return None
        return quote[:quote_size]

    def get_tdquote_bytes_from_req(self, req):
        '''
        Method get_tdquote_bytes_from_req retrieves the tdquote in bytes
        format from the tdx_report_req struct.
        struct tdx_quote_req {
            __u64 buf;
            __u64 len;
        };
        '''
        buf_addr, buf_len = struct.unpack("QQ", req)
        buf = (ctypes.c_char * buf_len).from_address(buf_addr)
        # sizeof(version + status + in_len + out_len) = 24
        # https://cdrdv2.intel.com/v1/dl/getContent/726792
        # Intel TDX Guest-Hypervisor Communication Interface v1.5
        #   Table 3-10: TDG.VP.VMCALL<GetQuote> - format of shared GPA
        data_len = buf_len - 24
        _, _, _, out_len, data = struct.unpack(f"QQII{data_len}s", buf)
        data_len = int.from_bytes(data[:4], "big")
        if data_len != out_len - 4:
            LOG.error("TD Quote data length sanity check failed")
            return None
        tdquote = self.qgs_msg_quote_resp(data[4:])
        return tdquote

    def process_output(self, rawdata) -> TdxQuote:
        """
        Process response data from IOCTL
        """
        tdquote_bytes = self.get_tdquote_bytes_from_req(rawdata)
        return TdxQuote(tdquote_bytes)
