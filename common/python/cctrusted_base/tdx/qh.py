"""
TDX Quote Related Helpers
"""



import ctypes
import logging
import struct

from cctrusted_base.quote import Quote, QuoteBody, QuoteHeader, QuoteSignature



LOG = logging.getLogger(__name__)


class TdxQuoteHeader(QuoteHeader):
    """
    Quote Header
    Definition reference:
    https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/TDX_Quoting_Library_API.pdf
    A.3. Version 4 Quote Format (TDX-ECDSA, SGX-ECDSA, and SGX-EPID)

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
        self._data = data
        #TODO: parse raw data according to TD Quote format

    def get_data(self) -> bytearray:
        """
        Get raw data
        """
        raise self._data



class TdxQuoteBody(QuoteBody):
    """
    Quote Body
    Definition reference:
    https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/TDX_Quoting_Library_API.pdf
    A.3. Version 4 Quote Format (TDX-ECDSA, SGX-ECDSA, and SGX-EPID)

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
    MROWNER         48              Byte Array      Software-defined ID for the TD’s owner
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
    """

    def __init__(self, data: bytearray):
        self._data = data
        #TODO: parse raw data according to TD Quote format

    def get_data(self) -> bytearray:
        """
        Get raw data
        """
        raise self._data



class TdxQuote(Quote):
    """
    TDX Quote
    """

    def __init__(self, data: bytearray):
        self._data = data
        # TODO: parse raw data into header, body and sigature

    def get_header(self) -> QuoteHeader:
        """
        Get TDX quote header
        """
        # TODO: parse the raw data to get header
        return None

    def get_body(self) -> QuoteBody:
        """
        Get TDX quote body
        """
        # TODO: parse the raw data to get body
        return None

    def get_sig(self) -> QuoteSignature:
        """
        Get TDX quote signature
        """
        # TODO: parse the raw data to get signature
        return None



class QuoteHelper:
    """
    Quote Helper
    Reference: Intel® TDX DCAP: Quote Generation Library and Quote Verification Library
    https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/TDX_Quoting_Library_API.pdf
    """

    # The length of the tdquote 4 pages
    TDX_QUOTE_LEN = 4 * 4096

    @staticmethod
    def qgs_msg_quote_req(tdreport):
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

    @staticmethod
    def qgs_msg_quote_resp(buf):
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

    @staticmethod
    def create_tdx_quote_req(tdreport, tdquote):
        '''
        Method create_tdx_quote_req creates a tdx_quote_req struct
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
        report_size = len(tdreport)
        version = 1
        status = 0
        in_len = 0
        out_len = 0

        qgs_msg = QuoteHelper.qgs_msg_quote_req(tdreport)
        in_len = len(qgs_msg) + 4

        tdquote_hdr = struct.pack(f"QQII4s{report_size}s", version, status, in_len, out_len,
            len(qgs_msg).to_bytes(4, "big"), qgs_msg)
        tdquote[:len(tdquote_hdr)] = tdquote_hdr
        req = struct.pack("QQ", ctypes.addressof(tdquote), QuoteHelper.TDX_QUOTE_LEN)
        return req

    @staticmethod
    def get_tdquote_bytes_from_req(req):
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
        tdquote = QuoteHelper.qgs_msg_quote_resp(data[4:])
        return tdquote
