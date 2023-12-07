"""
Manage the TDX Report
"""
import logging
from abc import ABC, abstractmethod
from cctrusted_base.binaryblob import BinaryBlob
from cctrusted_base.tdx.common import TDX_VERSION_1_0, TDX_VERSION_1_5, \
        TDX_REPORTDATA_LEN, TDX_REPORT_LEN

LOG = logging.getLogger(__name__)

class ModuleVersion:
    '''
    class ModuleVersion contains version infomation of tdx module
    '''

    VALID_SVN_LENGTH = 16

    def __init__(self, release_names: list[str], major: int, minor: int, is_debug: bool = False):
        self.release_names = release_names
        self.major = major
        self.minor = minor
        self.is_debug = is_debug

    @staticmethod
    def from_bytes(tee_tcb_svn: bytes):
        '''
        Method from_bytes parses bytes of the svn, if it
        is valid, return the instance of the module version.
        '''
        if len(tee_tcb_svn) != ModuleVersion.VALID_SVN_LENGTH:
            return None, False
        version_bytes = tee_tcb_svn[0:2]
        for version in VALID_MODULE_VERSIONS:
            if version.to_hex().to_bytes(2, byteorder='little') == version_bytes:
                return version, True
        return None, False

    def to_hex(self):
        '''
        Method to_hex converts the module version to the svn in hex.
        '''
        return self.major * 16 * 16 + self.minor

    def __str__(self):
        sep = " or "
        names = sep.join(self.release_names)
        return (f'module version: {{ '
                f'release_names: {names},'
                f'major: {self.major},'
                f'minor: {self.minor},'
                f'is_debug: {self.is_debug}'
                f' }}'
               )

VALID_MODULE_VERSIONS = [
    ModuleVersion(["1.0"], 0, 0, True),
    ModuleVersion(["1.0"], 0, 3),
    ModuleVersion(["1.4", "1.5"], 1, 0, True),
    ModuleVersion(["1.4", "1.5"], 1, 3),
    ModuleVersion(["2.0"], 2, 0, True),
    ModuleVersion(["2.0"], 2, 3),
]

class ReportMacStruct(BinaryBlob):
    """
    Struct REPORTMACSTRUCT
    """

    def __init__(self, data):
        super().__init__(data)
        self.report_type = None
        self.reserverd1 = None
        self.cpusvn = None
        self.tee_tcb_info_hash = None
        self.tee_info_hash = None
        self.report_data = None
        self.reserverd2 = None
        self.mac = None

    def parse(self):
        """
        parse the raw data for Struct REPORTMACSTRUCT

        Struct REPORTMACSTRUCT's layout:
        offset, len
        0x0,    0x8     report_type
        0x8,    0x8     reserverd1
        0x10,   0x10    cpusvn
        0x20,   0x30    tee_tcb_info_hash
        0x50,   0x30    tee_info_hash
        0x80,   0x40    report_data
        0xc0,   0x20    reserverd2
        0xe0,   0x20    mac
        """
        offset = 0

        self.report_type, offset = self.get_bytes(offset, 0x8)
        self.reserverd1, offset = self.get_bytes(offset, 0x8)
        self.cpusvn, offset = self.get_bytes(offset, 0x10)
        self.tee_tcb_info_hash, offset = self.get_bytes(offset, 0x30)
        self.tee_info_hash, offset = self.get_bytes(offset, 0x30)
        self.report_data, offset = self.get_bytes(offset, 0x40)
        self.reserverd2, offset = self.get_bytes(offset, 0x20)
        self.mac, offset = self.get_bytes(offset, 0x20)

class TeeTcbInfo(BinaryBlob):
    """
    Struct TEE_TCB_INFO
    """

    def __init__(self, data):
        super().__init__(data)
        self.module_version = None

        # real fields
        self.valid = None
        self.tee_tcb_svn = None
        self.mrseam = None
        self.mrsignerseam = None
        self.attributes = None
        self.tee_tcb_svn2 = None
        self.reserved = None

    def parse(self, tdx_version):
        """
        parse the raw data for Struct TEE_TCB_INFO

        Struct TEE_TCB_INFO's layout:
        offset, len
        0x0,    0x08    valid
        0x8,    0x10    tee_tcb_svn
        0x18,   0x30    mrseam
        0x48,   0x30    mrsignerseam
        0x78,   0x08    attributes

        # fileds in tdx v1.0
        0x80,   0x6f    reserved

        # fileds in tdx v1.5
        0x80,   0x10    tee_tcb_svn2
        0x90,   0x5f    reserved

        FIXME:  need spec reference to update info # pylint: disable=fixme
                about new field tee_tcb_svn2
        """
        offset = 0

        self.valid, offset = self.get_bytes(offset, 0x8)
        self.tee_tcb_svn, offset = self.get_bytes(offset, 0x10)
        self.mrseam, offset = self.get_bytes(offset, 0x30)
        self.mrsignerseam, offset = self.get_bytes(offset, 0x30)
        self.attributes, offset = self.get_bytes(offset, 0x8)

        if  tdx_version == TDX_VERSION_1_0:
            self.reserved, offset = self.get_bytes(offset, 0x6f)
        elif tdx_version == TDX_VERSION_1_5:
            self.tee_tcb_svn2, offset = self.get_bytes(offset, 0x10)
            self.reserved, offset = self.get_bytes(offset, 0x5f)

        # parse module svn
        self.module_version, _ = ModuleVersion.from_bytes(self.tee_tcb_svn)

class TdInfo(BinaryBlob):
    """
    Struct TDINFO_STRUCT
    """

    def __init__(self, data):
        super().__init__(data)
        # read fields
        self.attributes = None
        self.xfam = None
        self.mrtd = None
        self.mrconfigid = None
        self.mrowner = None
        self.mrownerconfig = None
        self.rtmr_0 = None
        self.rtmr_1 = None
        self.rtmr_2 = None
        self.rtmr_3 = None
        self.servtd_hash = None
        self.reserved = None

    def parse(self, tdx_version):
        '''
        parse the raw data for Struct TDINFO_STRUCT

        Struct TDINFO_STRUCT's layout:
        offset, len
        0x0,    0x8     attributes
        0x8,    0x8     xfam
        0x10,   0x30    mrtd
        0x40,   0x30    mrconfigid
        0x70,   0x30    mrowner
        0xa0,   0x30    mrownerconfig
        0xd0,   0x30    rtmr_0
        0x100,  0x30    rtmr_1
        0x130,  0x30    rtmr_2
        0x160,  0x30    rtmr_3

        # fields in tdx v1.0
        0x190,  0x70    reserved

        # fields in tdx v1.5
        0x190,  0x30    servtd_hash
        0x1c0,  0x40    reserved

        ref:
            Page 40 of Intel® TDX Module v1.5 ABI Specification
            from https://www.intel.com/content/www/us/en/developer/articles/technical/
            intel-trust-domain-extensions.html
        '''

        offset = 0

        self.attributes, offset = self.get_bytes(offset, 0x8)
        self.xfam, offset = self.get_bytes(offset, 0x8)
        self.mrtd, offset = self.get_bytes(offset, 0x30)
        self.mrconfigid, offset = self.get_bytes(offset, 0x30)
        self.mrowner, offset = self.get_bytes(offset, 0x30)
        self.mrownerconfig, offset = self.get_bytes(offset, 0x30)
        self.rtmr_0, offset = self.get_bytes(offset, 0x30)
        self.rtmr_1, offset = self.get_bytes(offset, 0x30)
        self.rtmr_2, offset = self.get_bytes(offset, 0x30)
        self.rtmr_3, offset = self.get_bytes(offset, 0x30)

        if  tdx_version == TDX_VERSION_1_0:
            self.reserved, offset = self.get_bytes(offset, 0x70)
        elif  tdx_version == TDX_VERSION_1_5:
            self.servtd_hash, offset = self.get_bytes(offset, 0x30)
            self.reserved, offset = self.get_bytes(offset, 0x40)

class TdReport(BinaryBlob):

    def __init__(self, data):
        super().__init__(data)
        self.report_mac_struct = None
        self.tee_tcb_info = None
        self.reserved = None
        self.td_info = None

    def parse(self, version):
        """
        Parse structure
        """
        offset = 0

        data, offset = self.get_bytes(offset, 0x100)
        self.report_mac_struct = ReportMacStruct(data)
        self.report_mac_struct.parse()

        data, offset = self.get_bytes(offset, 0xef)
        self.tee_tcb_info = TeeTcbInfo(data)
        self.tee_tcb_info.parse(version)

        data, offset = self.get_bytes(offset, 0x11)
        self.reserved = data

        data, offset = self.get_bytes(offset, 0x200)
        self.td_info = TdInfo(data)
        self.td_info.parse(version)

class TdxReportReq(ABC):

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
        Return the request data for TDREPORT
        """
        raise NotImplementedError("Should be implemented by inherited class")

    @abstractmethod
    def process_output(self, rawdata) -> TdReport:
        """
        Process response data from IOCTL or sysfs
        """
        raise NotImplementedError("Should be implemented by inherited class")

class TdxReportReq10(TdxReportReq):

    def __init__(self):
        TdxReportReq.__init__(self, TDX_VERSION_1_0)

    def prepare_reqbuf(self, report_data=None) -> bytearray:
        assert False, "Need implement later"

    def process_output(self, rawdata) -> TdReport:
        assert False, "Need implement later"

class TdxReportReq15(TdxReportReq):

    def __init__(self):
        TdxReportReq.__init__(self, TDX_VERSION_1_5)

    def prepare_reqbuf(self, report_data=None) -> bytearray:
        length = 0
        if  report_data is not None:
            length = len(report_data)

        if length > TDX_REPORTDATA_LEN:
            LOG.error("Input report_data is longer than TDX_REPORTDATA_LEN")
            return None

        req = bytearray(TDX_REPORTDATA_LEN + TDX_REPORT_LEN)
        for index in range(length):
            req[index] = report_data[index]
        return req

    def process_output(self, rawdata) -> TdReport:
        """
        Process response data from IOCTL or sysfs
        """
        report_bytes = rawdata[TDX_REPORTDATA_LEN:]
        report_obj = TdReport(report_bytes)
        report_obj.parse(self.version)
        return report_obj
