"""
TDX Quote related classes.
"""

import ctypes
import logging
import struct

from abc import ABC, abstractmethod
from enum import Enum
from cctrusted_base.api import CCTrustedApi
from cctrusted_base.binaryblob import BinaryBlob
from cctrusted_base.ccreport import CcReport, CcReportData, CcReportSignature
from cctrusted_base.tdx.common import TDX_QUOTE_VERSION_4, TDX_QUOTE_VERSION_5
from cctrusted_base.tdx.common import TDX_VERSION_1_0, TDX_VERSION_1_5

LOG = logging.getLogger(__name__)

DUMP_FORMAT_RAW = "raw"
DUMP_FORMAT_HUMAN = "human"

def info(s: str):
    """Local wrapper function to log information."""
    LOG.info(s)

class AttestationKeyType(Enum):
    """Attestation Key Type."""
    ECDSA_P256 = 2
    ECDSA_P384 = 3

class TeeType(Enum):
    """TEE Type."""
    TEE_SGX = 0x00000000
    TEE_TDX = 0x00000081

QE_VENDOR_INTEL_SGX = "939a7233f79c4ca9940a0db3957f0607"
"""QE Vendor ID. Unique identifier of the QE Vendor.

Note: Each vendor that decides to provide a customized Quote data
structure should have unique ID.

    e.g. Value: 939A7233F79C4CA9940A0DB3957F0607 (Intel® SGX QE Vendor)
"""

class QeCertDataType(Enum):
    """QE Certification Data Type.

    Definition reference:
    https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf
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
    """TD Quote Header.

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
    """

    def __init__(self, data: bytearray):
        """Initialize attributes according to spec.

        It saves raw data in the attribute of its super class and parses
        the raw data and save each field as the attributes.

        Args:
            data: A bytearray of the raw data.
        """
        super().__init__(data)
        v = memoryview(self.data)
        self.ver = int.from_bytes(v[0:2].tobytes(), "little")
        self.ak_type = AttestationKeyType(int.from_bytes(v[2:4].tobytes(), "little"))
        self.tee_type = TeeType(int.from_bytes(v[4:8].tobytes(), "little"))
        self.reserved_1 = v[8:10].tobytes()
        self.reserved_2 = v[10:12].tobytes()
        self.qe_vendor = v[12:28].tobytes()
        self.user_data = v[28:].tobytes()

    def dump(self, fmt=DUMP_FORMAT_RAW, indent=""):
        """Dump data.

        Args:
            fmt: A string indicating the output format.
                    DUMP_FORMAT_RAW: dump in hex strings.
                    DUMP_FORMAT_HUMAN: dump in human readable texts.
            indent: A string indicating the prefixed indent for each line.
        """
        info(f'{indent}TD Quote Header:')
        if fmt == DUMP_FORMAT_HUMAN:
            i = indent + "  "
            info(f'{i}Header Version: {self.ver}')
            info(f'{i}Attestation Key Type: {self.ak_type}')
            info(f'{i}TEE Type: {self.tee_type}')
            info(f'{i}Reserved 1: 0x{self.reserved_1.hex()}')
            info(f'{i}Reserved 2: 0x{self.reserved_2.hex()}')
            qe_vendor_name = ""
            if QE_VENDOR_INTEL_SGX == self.qe_vendor.hex():
                # This is the only defined QE Vendor so far according to the spec
                # The link to the spec is given in the docstring of TdxQuoteHeader.
                qe_vendor_name = " # Intel® SGX QE Vendor"
            info(f'{i}QE Vendor ID: 0x{self.qe_vendor.hex()}{qe_vendor_name}')
            info(f'{i}User Data: 0x{self.user_data.hex()}')
        else:
            # Default output raw data in hex string
            super().dump()

class TdxQuoteTeeTcbSvn(BinaryBlob):
    """TEE TCB SVN structure in TD Quote Body.

    Atrributes:
        data: A bytearray fo the raw data.

    Definition reference:
    https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf
    A.3.3. TEE_TCB_SVN
    """

    def __init__(self, data: bytearray):
        """Initialize with raw data.

        Args:
            data: A bytearray of the raw data.
        """
        super().__init__(data)

    def dump(self, fmt=DUMP_FORMAT_RAW, indent=""):
        """Dump data.

        Args:
            fmt: A string indicating the output format.
                    DUMP_FORMAT_RAW: dump in hex strings.
                    DUMP_FORMAT_HUMAN: dump in human readable texts.
            indent: A string indicating the prefixed indent for each line.
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

class TdxQuoteBody(CcReportData):
    """TD Quote Body.

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
        tee_tcb_svn: A ``TdxQuoteTeeTcbSvn`` describing the TCB of TDX.
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
    """

    def __init__(self, data: bytearray):
        """Initialize attributes according to spec.

        It saves raw data in the attribute of its super class and parses
        the raw data and save each field as the attributes.

        Args:
            data: A bytearray of the raw data.
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
        """Dump data.

        Args:
            fmt: A string indicating the output format.
                    DUMP_FORMAT_RAW: dump in hex strings.
                    DUMP_FORMAT_HUMAN: dump in human readable texts.
            indent: A string indicating the prefixed indent for each line.
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

class TdxEnclaveReportBody(BinaryBlob):
    """TD Quote Enclave Report Body.

    Atrributes:
        cpu_svn: Bytes indicating the CPU SVN
        miscselect: An integer indicating the MISCSELECT
        reserved_1: Reserved.
        attributes: Bytes storing the Attributes.
        mrenclave: Bytes storing the MRENCLAVE.
        reserved_2: Reserved.
        mrsigner: Bytes storing the MRSIGNER.
        reserved_3: Reserved.
        isv_prodid: An integer indicating the ISV ProdID.
        isv_svn: And integer indicating the ISV SVN.
        reserved_4: Reserved.
        report_data: Report Data.

    Definition reference:
    https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf
    A.3.10. Enclave Report Body
    """

    def __init__(self, data: bytearray):
        """Initialize attributes according to spec.

        It saves raw data in the attribute of its super class and parses
        the raw data and save each field as the attributes.

        Args:
            data: A bytearray of the raw data.
        """
        super().__init__(data)
        v = memoryview(self.data)
        self.cpu_svn = v[0:16].tobytes()
        self.miscselect = int.from_bytes(v[16:20].tobytes(), "little")
        self.reserved_1 = v[20:48].tobytes()
        self.attributes = v[48:64].tobytes()
        self.mrenclave = v[64:96].tobytes()
        self.reserved_2 = v[96:128].tobytes()
        self.mrsigner = v[128:160].tobytes()
        self.reserved_3 = v[160:256].tobytes()
        self.isv_prodid = int.from_bytes(v[256:258].tobytes(), "little")
        self.isv_svn = int.from_bytes(v[258:260].tobytes(), "little")
        self.reserved_4 = v[260:320].tobytes()
        self.report_data = v[320:384].tobytes()

    def dump(self, fmt=DUMP_FORMAT_RAW, indent=""):
        """Dump data.

        Args:
            fmt: A string indicating the output format.
                    DUMP_FORMAT_RAW: dump in hex strings.
                    DUMP_FORMAT_HUMAN: dump in human readable texts.
            indent: A string indicating the prefixed indent for each line.
        """
        info(f'{indent}{type(self).__name__}:')
        if fmt == DUMP_FORMAT_HUMAN:
            i = indent + "  "
            info(f'{i}CPU SVN: 0x{self.cpu_svn.hex()}')
            info(f'{i}MISCSELECT: {self.miscselect}')
            info(f'{i}Reserved: 0x{self.reserved_1.hex()}')
            info(f'{i}Attributes: 0x{self.attributes.hex()}')
            info(f'{i}MRENCLAVE: 0x{self.mrenclave.hex()}')
            info(f'{i}Reserved: 0x{self.reserved_2.hex()}')
            info(f'{i}MRSIGNER: 0x{self.mrsigner.hex()}')
            info(f'{i}Reserved: 0x{self.reserved_3.hex()}')
            info(f'{i}ISV ProdID: {self.isv_prodid}')
            info(f'{i}ISV SVN: {self.isv_svn}')
            info(f'{i}Reserved: 0x{self.reserved_4.hex()}')
            info(f'{i}Report Data: 0x{self.report_data.hex()}')
        else:
            # Default output raw data in hex string
            super().dump()

class TdxQuoteQeReportCert(BinaryBlob):
    """TD Quote QE Report Certification Data.

    Atrributes:
        qe_report: A ``TdxEnclaveReportBody`` storing the SGX Report of the
                   Quoting Enclave that generated an Attestation Key.
        qe_report_sig: A bytearray storing ECDSA signature over the QE Report
                       calculated using the Provisioning Certification Key (PCK).
        qe_auth_data: A bytearray storing the QE Authentication Data.
        qe_cert_data: A ``TdxQuoteQeCert`` storing the QE Certification Data.

    Definition reference:
    https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf
    A.3.11. QE Report Certification Data
    """

    def __init__(self, data: bytearray):
        """Initialize attributes according to spec.

        It saves raw data in the attribute of its super class and parses
        the raw data and save each field as the attributes.

        Args:
            data: A bytearray of the raw data.
        """
        super().__init__(data)
        v = memoryview(self.data)
        self.qe_report = TdxEnclaveReportBody(v[0:384].tobytes())
        self.qe_report_sig = v[384:448].tobytes()
        auth_data_size = int.from_bytes(v[448:450], "little")
        data_end = 450 + auth_data_size
        if auth_data_size > 0:
            self.qe_auth_data = v[450:(data_end)].tobytes()
        else:
            self.qe_auth_data = None
        self.qe_cert_data = TdxQuoteQeCert(v[data_end:].tobytes())

    def dump(self, fmt=DUMP_FORMAT_RAW, indent=""):
        """Dump data.

        Args:
            fmt: A string indicating the output format.
                    DUMP_FORMAT_RAW: dump in hex strings.
                    DUMP_FORMAT_HUMAN: dump in human readable texts.
            indent: A string indicating the prefixed indent for each line.
        """
        info(f'{indent}{type(self).__name__}:')
        if fmt == DUMP_FORMAT_HUMAN:
            i = indent + "  "
            self.qe_report.dump(DUMP_FORMAT_HUMAN, i)
            info(f'{i}Quote QE Report Signature: 0x{self.qe_report_sig.hex()}')
            if self.qe_auth_data is not None:
                info(f'{i}Quote QE Authentication Data: 0x{self.qe_auth_data.hex()}')
            else:
                info(f'{i}Quote QE Authentication Data: None')
            self.qe_cert_data.dump(DUMP_FORMAT_HUMAN, i)
        else:
            # Default output raw data in hex string
            super().dump()

class TdxQuoteQeCert(BinaryBlob):
    """TD Quote QE Certification Data.

    Attributes:
        cert_type: A ``QeCertDataType`` determining the type of data required to verify the
                   QE Report Signature in the Quote Signature Data structure.
        cert_data: A ``TdxQuoteQeReportCert`` storing the data required to verify the QE
                   Report Signature depending on the value of the Certification Data Type.

    Definition reference:
    https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf
    A.3.9. QE Certification Data - Version 4
    """

    def __init__(self, data: bytearray):
        """Initialize attributes according to spec.

        It saves raw data in the attribute of its super class and parses
        the raw data and save each field as the attributes.

        Args:
            data: A bytearray of the raw data.
        """
        super().__init__(data)
        v = memoryview(self.data)
        self.cert_type = QeCertDataType(int.from_bytes(v[0:2].tobytes(), "little"))
        cert_size = int.from_bytes(v[2:6].tobytes(), "little")
        cert_data_end = 6 + cert_size
        if self.cert_type == QeCertDataType.QE_REPORT_CERT:
            self.cert_data = TdxQuoteQeReportCert(v[6:cert_data_end].tobytes())
        else:
            self.cert_data = v[6:cert_data_end].tobytes()

    def dump(self, fmt=DUMP_FORMAT_RAW, indent=""):
        """Dump data.

        Args:
            fmt: A string indicating the output format.
                    DUMP_FORMAT_RAW: dump in hex strings.
                    DUMP_FORMAT_HUMAN: dump in human readable texts.
            indent: A string indicating the prefixed indent for each line.
        """
        info(f'{indent}{type(self).__name__}:')
        if fmt == DUMP_FORMAT_HUMAN:
            i = indent + "  "
            info(f'{i}Quote QE Cert Data Type: {self.cert_type}')
            if self.cert_type == QeCertDataType.QE_REPORT_CERT:
                self.cert_data.dump(fmt, i)
            elif self.cert_type == QeCertDataType.PCK_CERT_CHAIN:
                info(f'{i}PCK Cert Chain (PEM, Leaf||Intermediate||Root):')
                info(f'{self.cert_data.decode("utf-8")}')
            else:
                info(f'{i}Quote QE Cert Data: {self.cert_data}')
        else:
            # Default output raw data in hex string
            super().dump()

class TdxQuoteEcdsa256Sigature(CcReportSignature):
    """TD Quote ECDSA 256-bit Quote Signature.

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
    A.3.8. ECDSA 256-bit Quote Signature Data Structure - Version 4
    """

    def __init__(self, data: bytearray):
        """Initialize attributes according to spec.

        It saves raw data in the attribute of its super class and parses
        the raw data and save each field as the attributes.

        Args:
            data: A bytearray of the raw data.
        """
        # TODO: parse more details according to the spec.
        super().__init__(data)
        v = memoryview(self.data)
        self.sig = v[0:64].tobytes()
        self.ak = v[64:128].tobytes()
        self.qe_cert = TdxQuoteQeCert(v[128:].tobytes())

    def dump(self, fmt=DUMP_FORMAT_RAW, indent=""):
        """Dump data.

        Args:
            fmt: A string indicating the output format.
                    DUMP_FORMAT_RAW: dump in hex strings.
                    DUMP_FORMAT_HUMAN: dump in human readable texts.
            indent: A string indicating the prefixed indent for each line.
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

class TdxQuoteSignature(CcReportSignature):
    """TD Quote Signature."""

    def __init__(self, data: bytearray):
        """Initialize with raw data.

        Args:
            data: A bytearray of the raw data.
        """
        super().__init__(data)

    def dump(self, fmt=DUMP_FORMAT_RAW, indent=""):
        """Dump data.

        Args:
            fmt: A string indicating the output format.
                    DUMP_FORMAT_RAW: dump in hex strings.
                    DUMP_FORMAT_HUMAN: dump in human readable texts.
            indent: A string indicating the prefixed indent for each line.
        """
        info(f'{indent}TD Quote Signature:')
        if fmt == DUMP_FORMAT_HUMAN:
            info("")
        else:
            super().dump()

class TdxQuote(CcReport):
    """TDX Quote.

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
    """

    def __init__(self, data: bytearray):
        """Initialize attributes according to spec.

        It saves raw data in the attribute of its super class and parses
        the raw data and save each field as the attributes.

        Args:
            data: A bytearray of the raw data.
        """
        super().__init__(data, CCTrustedApi.TYPE_CC_TDX)
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

    def get_quoted_data(self) -> CcReportData:
        """Get TD Quoted Data.

        Returns:
            The intance of its ``QuoteData``.
        """
        return self.body

    def get_sig(self) -> CcReportSignature:
        """Get TD Quote signature.

        Returns:
            The instance of its ``QuoteSignature``.
        """
        return self.sig

    def dump(self, is_raw=True) -> None:
        """Dump Quote Data.

        Args:
            is_raw:
                True: dump in hex strings
                False: dump in human readable texts
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
    """TDX Quote Request."""

    def __init__(self, ver):
        """Initialize TDX Quote Request.

        Args:
            ver: A string indicating the version of TDX.
                 TDX_VERSION_1_0 or TDX_VERSION_1_5.
        """
        self._version = ver

    @property
    def version(self):
        """The TDX version.

        Returns:
            The version of TDX.
        """
        return self._version

    @abstractmethod
    def prepare_reqbuf(self, report_data=None) -> bytearray:
        """Prepare request buffer.

        Args:
            report_data: TD report related data.

        Returns:
            A bytearray storing the request data for TD Quote.
        """
        raise NotImplementedError("Should be implemented by inherited class")

    @abstractmethod
    def process_output(self, rawdata) -> TdxQuote:
        """Process response data from IOCTL.

        Args:
            rawdata: A bytearray storing the response data from IOCTL.

        Returns:
            An instance of ``TdxQuote``.
        """
        raise NotImplementedError("Should be implemented by inherited class")

class TdxQuoteReq10(TdxQuoteReq):
    """TDX Quote Request for TDX 1.0."""

    def __init__(self):
        """Initialize TDX Quote Request."""
        TdxQuoteReq.__init__(self, TDX_VERSION_1_0)

    def prepare_reqbuf(self, report_data=None) -> bytearray:
        """Prepare request buffer.

        Args:
            report_data: TD report related data.

        Returns:
            A bytearray storing the request data for TD Quote.
        """
        assert False, "Need implement later"

    def process_output(self, rawdata) -> TdxQuote:
        """Process response data from IOCTL.

        Args:
            rawdata: A bytearray storing the response data from IOCTL.

        Returns:
            An instance of ``TdxQuote``.
        """
        assert False, "Need implement later"

class TdxQuoteReq15(TdxQuoteReq):
    """TDX Quote Request for TDX 1.5."""

    # The length of the tdquote 4 pages
    TDX_QUOTE_LEN = 4 * 4096

    def __init__(self):
        """Initialize TDX Quote Request."""
        TdxQuoteReq.__init__(self, TDX_VERSION_1_5)
        self.tdquote = None

    def qgs_msg_quote_req(self, tdreport):
        """Generage QGS message to get TD Quote.

        Args:
            tdreport: Bytes of TD Report data.

        Returns:
            Bytes of the QGS message.

        References:
        https://github.com/intel/SGXDataCenterAttestationPrimitives
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
        """
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
        """Prepare request buffer.

        Args:
            report_data: TD report related data.

        Returns:
            A bytearray storing the request data for TD Quote.

        It creates a tdx_quote_req struct with report_data. Refer TDX
        Guest Hypervisor Communication Interface (GHCI) specification
        for details.
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

        References:
        https://cdrdv2.intel.com/v1/dl/getContent/726792
        Intel TDX Guest-Hypervisor Communication Interface v1.5
        """

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

    def qgs_msg_quote_resp(self, buf) -> bytes:
        """Get Quote from the response of QGS messages.

        Args:
            buf: Bytes storing the QGS message structs.

        Returns:
            Bytes of TD Quote data.

        References:
        https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteGeneration/quote_wrapper/qgs_msg_lib/inc/qgs_msg_lib.h

        typedef struct _qgs_msg_header_t {
            uint16_t major_version;
            uint16_t minor_version;
            uint32_t type;
            uint32_t size; // size of the whole message, include this header, in byte
            uint32_t error_code; // used in response only
        } qgs_msg_header_t;

        typedef struct _qgs_msg_get_quote_resp_s {
            qgs_msg_header_t header;    // header.type = GET_QUOTE_RESP
            uint32_t selected_id_size;  // can be 0 in case only one id is sent in request
            uint32_t quote_size;        // length of quote_data, in byte
            uint8_t id_quote[];         // selected id followed by quote
        } qgs_msg_get_quote_resp_t;
        """
        msg_size = len(buf) - (16 + 8)
        major_version, minor_version, msg_type, msg_size, error_code, _, quote_size, quote = \
            struct.unpack(f"2H5I{msg_size}s", buf)
        if major_version != 1 and minor_version != 0 and msg_type != 1 and error_code != 0:
            return None
        return quote[:quote_size]

    def get_tdquote_bytes_from_req(self, req) -> bytes:
        """Get the TD Quote in bytes format from the tdx_quote_req struct.

        Args:
            req: Bytes of the request struct "tdx_quote_req".

        Returns:
            Bytes of TD Quote data. None if it fails.

        References:
        Kernel source in include/uapi/linux/tdx-guest.h:

            struct tdx_quote_req {
                __u64 buf;
                __u64 len;
            };

        struct tdx_quote_req: Request struct for TDX_CMD_GET_QUOTE IOCTL.
        buf: Address of user buffer in the format of struct tdx_quote_buf.
            Upon successful completion of IOCTL, output is copied back to
            the same buffer (in struct tdx_quote_buf.data).
        len: Length of the Quote buffer.
        """
        buf_addr, buf_len = struct.unpack("QQ", req)
        buf = (ctypes.c_char * buf_len).from_address(buf_addr)
        # Kernel source in include/uapi/linux/tdx-guest.h:
        # struct tdx_quote_buf {
        #     __u64 version;
        #     __u64 status;
        #     __u32 in_len;
        #     __u32 out_len;
        #     __u64 data[];
        # };
        # sizeof(version + status + in_len + out_len) = 24
        # https://cdrdv2.intel.com/v1/dl/getContent/726792
        # Intel TDX Guest-Hypervisor Communication Interface v1.5
        #   Table 3-10: TDG.VP.VMCALL<GetQuote> - format of shared GPA
        #       Data offset (bytes) is 24
        #       Data length is "Size of shared GPA - 24"
        data_len = buf_len - 24
        _, status_code, _, out_len, data = struct.unpack(f"QQII{data_len}s", buf)
        if status_code != 0:
            # https://cdrdv2.intel.com/v1/dl/getContent/726792
            # Intel TDX Guest-Hypervisor Communication Interface v1.5
            #   Table 3-11: TDG.VP.VMCALL<GetQuote> - GetQuote Status Code
            LOG.error("Fail to get quote! Status Code: 0x%x", status_code)
            return None
        data_len = int.from_bytes(data[:4], "big")
        if data_len != out_len - 4:
            LOG.error("TD Quote data length sanity check failed")
            return None
        tdquote = self.qgs_msg_quote_resp(data[4:])
        return tdquote

    def process_output(self, rawdata) -> TdxQuote:
        """Process response data from IOCTL.

        Args:
            rawdata: A bytearray storing the response data from IOCTL.

        Returns:
            An instance of ``TdxQuote``. Return None if it fails.
        """
        tdquote_bytes = self.get_tdquote_bytes_from_req(rawdata)
        if tdquote_bytes is None:
            return None
        return TdxQuote(tdquote_bytes)
