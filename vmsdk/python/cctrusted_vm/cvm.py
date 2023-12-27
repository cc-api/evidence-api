"""
Confidential VM class manages following items:

1. Confidential device node like /dev/tdx-guest or /dev/sev-guest
2. Event log table from memory
3. IMR (integrated measurement register)

"""
import base64
import hashlib
import os
import logging
import struct
import fcntl
from abc import abstractmethod
from cctrusted_base.imr import TdxRTMR,TcgIMR
from cctrusted_base.quote import Quote
from cctrusted_base.tcg import TcgAlgorithmRegistry
from cctrusted_base.tdx.common import TDX_VERSION_1_0, TDX_VERSION_1_5
from cctrusted_base.tdx.quote import TdxQuoteReq10, TdxQuoteReq15
from cctrusted_base.tdx.report import TdxReportReq10, TdxReportReq15

LOG = logging.getLogger(__name__)

class ConfidentialVM:

    TYPE_CC_NONE = -1
    TYPE_CC_TDX = 0
    TYPE_CC_SEV = 1
    TYPE_CC_CCA = 2

    TYPE_CC_STRING = {
        TYPE_CC_TDX: "TDX",
        TYPE_CC_SEV: "SEV",
        TYPE_CC_CCA: "CCA"
    }

    _inst = None

    def __init__(self, cctype):
        self._cc_type:int = cctype
        self._is_init:bool = False
        self._imrs:dict[int, TcgIMR] = {}
        self._cc_event_log:bytes = None

    @property
    def cc_type(self) -> int:
        """CC type like TYPE_CC_TDX, TYPE_CC_SEV etc."""
        return self._cc_type

    @property
    @abstractmethod
    def default_algo_id(self):
        """Default algorithms ID supported by this Confidential VM."""
        raise NotImplementedError("Should be implemented by inherited class")

    @property
    @abstractmethod
    def version(self):
        """Version of CC VM."""
        raise NotImplementedError("Should be implemented by inherited class")

    @property
    def imrs(self) -> list[TcgIMR]:
        """The array of integrated measurement registers (IMR)."""
        return self._imrs

    @property
    def cc_type_str(self):
        """the CC type string."""
        return ConfidentialVM.TYPE_CC_STRING[self.cc_type]

    @property
    def cc_event_log(self):
        """event log data blob."""
        return self._cc_event_log

    def init(self) -> bool:
        """Initialize the CC stub and environment.

        Returns:
            Success or not
        """
        if self._is_init:
            return True

        if not self.process_cc_report():
            return False

        if not self.process_eventlog():
            return False

        self._is_init = True
        return True

    @staticmethod
    def detect_cc_type():
        """Detect the type of current confidential VM"""
        # TODO: refine the justification
        for devpath in TdxVM.DEVICE_NODE_PATH.values():
            if os.path.exists(devpath):
                return ConfidentialVM.TYPE_CC_TDX
        return ConfidentialVM.TYPE_CC_NONE

    @abstractmethod
    def process_cc_report(self) -> bool:
        """Process the confidential computing REPORT.

        Returns:
            Success or not.
        """
        raise NotImplementedError("Should be implemented by inherited class")

    @abstractmethod
    def process_eventlog(self) -> bool:
        """Process the event log.

        Returns:
            Success or not.
        """
        raise NotImplementedError("Should be implemented by inherited class")

    @abstractmethod
    def get_quote(self, nonce: bytearray, data: bytearray, extraArgs) -> Quote:
        """Get the quote for given nonce and data.

        The quote is signing of attestation data (IMR values or hashes of IMR
        values), made by a trusted foundation (TPM) using a key trusted by the
        verifier.

        Different trusted foundation may use different quote format.

        Args:
            nonce (bytearray): against replay attacks.
            data (bytearray): user data
            extraArgs: for TPM, it will be given list of IMR/PCRs

        Returns:
            The ``Quote`` object.
        """
        raise NotImplementedError("Should be implemented by inherited class")

    def dump(self):
        """Dump confidential VM information."""
        LOG.info("======================================")
        LOG.info("CVM type = %s", self.cc_type_str)
        LOG.info("CVM version = %s", self.version)
        LOG.info("======================================")

    @staticmethod
    def inst():
        """Singleton interface for the instance of CcLinuxStub"""
        if ConfidentialVM._inst is None:
            cc_type = ConfidentialVM.detect_cc_type()
            if cc_type is ConfidentialVM.TYPE_CC_TDX:
                obj = TdxVM()
            if obj.init():
                ConfidentialVM._inst = obj
            else:
                LOG.error("Fail to initialize the confidential VM.")
        return ConfidentialVM._inst

class TdxVM(ConfidentialVM):

    DEVICE_NODE_PATH = {
        TDX_VERSION_1_0: "/dev/tdx-guest",
        TDX_VERSION_1_5: "/dev/tdx_guest"
    }

    IOCTL_GET_REPORT = {
        TDX_VERSION_1_0: int.from_bytes(struct.pack('Hcb', 0x08c0, b'T', 1), 'big'),
        TDX_VERSION_1_5: int.from_bytes(struct.pack('Hcb', 0x40c4, b'T', 1),'big')
    }
    """
    TDX v1.0 reference: arch/x86/include/uapi/asm/tdx.h in kernel source
    TDX ioctl command layout (bits):
    command               dir(2)  size(14)                    type(8) nr(8)
    TDX_CMD_GET_REPORT    11      00,0000,0000,1000 (0xc008)  b'T'    0000,0001 (1)
    Convert the higher 16 bits from little-endian to big-endian:
    0xc008 -> 0x08c0

    TDX v1.5 reference: include/uapi/linux/tdx-guest.h in kernel source
    TDX ioctl command layout (bits):
    command               dir(2)  size(14bit)                 type(8bit)  nr(8bit)
    TDX_CMD_GET_REPORT0   11      00,0100,0100,0000 (0xc440)  b'T'        0000,0001 (1)
    Convert the higher 16 bits from little-endian to big-endian:
    0xc440 -> 0x40c4
    """

    IOCTL_GET_QUOTE = {
        TDX_VERSION_1_0: int.from_bytes(struct.pack('Hcb', 0x0880, b'T', 2), 'big'),
        TDX_VERSION_1_5: int.from_bytes(struct.pack('Hcb', 0x1080, b'T', 4),'big')
    }
    """
    TDX v1.0 reference: arch/x86/include/uapi/asm/tdx.h in kernel source
    TDX ioctl command layout (bits):
    command               dir(2)  size(14)                    type(8) nr(8)
    TDX_CMD_GET_QUOTE     10      00,0000,0000,1000 (0x8008)  b'T'    0000,0010 (2)
    Convert the higher 16 bits from little-endian to big-endian:
    0x8008 -> 0x0880

    TDX v1.5 Reference: include/uapi/linux/tdx-guest.h in kernel source
    TDX ioctl command layout (bits):
    command               dir(2)  size(14bit)                 type(8bit)  nr(8bit)
    TDX_CMD_GET_QUOTE     10      00,0000,0001,0000 (0x8010)  b'T'        0000,0100 (4)
    Convert the higher 16 bits from little-endian to big-endian
    0x8010 -> 0x1080
    """

    # The length of the tdquote 4 pages
    TDX_QUOTE_LEN = 4 * 4096

    # ACPI table containing the event logs
    ACPI_TABLE_FILE = "/sys/firmware/acpi/tables/CCEL"
    ACPI_TABLE_DATA_FILE = "/sys/firmware/acpi/tables/data/CCEL"

    def __init__(self):
        ConfidentialVM.__init__(self, ConfidentialVM.TYPE_CC_TDX)
        self._version:str = None
        self._tdreport = None

    @property
    def version(self):
        if self._version is None:
            for key, value in TdxVM.DEVICE_NODE_PATH.items():
                if os.path.exists(value):
                    self._version = key
        return self._version

    @property
    def default_algo_id(self):
        return TcgAlgorithmRegistry.TPM_ALG_SHA384

    @property
    def tdreport(self):
        """TDREPORT structure"""
        return self._tdreport

    def process_cc_report(self) -> bool:
        """Process the confidential computing REPORT."""
        dev_path = self.DEVICE_NODE_PATH[self.version]
        try:
            tdx_dev = os.open(dev_path, os.O_RDWR)
        except (PermissionError, IOError, OSError):
            LOG.error("Fail to open device node %s", dev_path)
            return False

        LOG.debug("Successful open device node %s", dev_path)

        if self.version is TDX_VERSION_1_0:
            tdreport_req = TdxReportReq10()
        elif self.version is TDX_VERSION_1_5:
            tdreport_req = TdxReportReq15()

        # pylint: disable=E1111
        reqbuf = tdreport_req.prepare_reqbuf()
        try:
            fcntl.ioctl(tdx_dev, self.IOCTL_GET_REPORT[self.version], reqbuf)
        except OSError:
            LOG.error("Fail to execute ioctl for file %s", dev_path)
            os.close(tdx_dev)
            return False

        LOG.debug("Successful read TDREPORT from %s.", dev_path)
        os.close(tdx_dev)

        # pylint: disable=E1111
        tdreport = tdreport_req.process_output(reqbuf)
        if tdreport is not None:
            LOG.debug("Successful parse TDREPORT.")

        # process IMR
        self._tdreport = tdreport
        self._imrs[0] = TdxRTMR(0, tdreport.td_info.rtmr_0)
        self._imrs[1] = TdxRTMR(1, tdreport.td_info.rtmr_1)
        self._imrs[2] = TdxRTMR(2, tdreport.td_info.rtmr_2)
        self._imrs[3] = TdxRTMR(3, tdreport.td_info.rtmr_3)

        return True

    def process_eventlog(self) -> bool:
        """Process the event log

        Fetch boot time event logs from CCEL table and CCEL data file
        Save contents into TdxVM attributes

        Args:
            None

        Returns:
            A boolean indicating the status of process_eventlog
            True means the function runs successfully
            False means error occurred in event log processing

        Raises:
            PermissionError: An error occurred when accessing CCEL files
        """

        # verify if CCEL files existed
        if not os.path.exists(TdxVM.ACPI_TABLE_FILE):
            LOG.error("Failed to find TDX CCEL table at %s", TdxVM.ACPI_TABLE_FILE)
            return False

        if not os.path.exists(TdxVM.ACPI_TABLE_DATA_FILE):
            LOG.error("Failed to find TDX CCEL data file at %s", TdxVM.ACPI_TABLE_DATA_FILE)
            return False

        try:
            with open(TdxVM.ACPI_TABLE_FILE, "rb") as f:
                ccel_data = f.read()
                assert len(ccel_data) > 0 and ccel_data[0:4] == b'CCEL', \
                    "Invalid CCEL table"
        except (PermissionError, OSError):
            LOG.error("Need root permission to open file %s", TdxVM.ACPI_TABLE_FILE)
            return False

        try:
            with open(TdxVM.ACPI_TABLE_DATA_FILE, "rb") as f:
                self._cc_event_log = f.read()
                assert len(self._cc_event_log) > 0
        except (PermissionError, OSError):
            LOG.error("Need root permission to open file %s", TdxVM.ACPI_TABLE_DATA_FILE)
            return False
        return True


    def get_quote(self, nonce: bytearray, data: bytearray, extraArgs) -> Quote:
        """Get quote.

        This depends on Quote Generation Service. Please reference "Whitepaper:
        Linux* Stacks for Intel® Trust Domain Extensions (4.3 Attestation)" for
        settings:
        https://www.intel.com/content/www/us/en/content-details/790888/whitepaper-linux-stacks-for-intel-trust-domain-extensions-1-5.html

        1. Set up the host: follow 4.3.1 ~ 4.3.4.
        2. Set up the guest: follow "Approach 2: Get quote via TDG.VP.VMCALL.GETQUOTE"
        in "4.3.5.1 Launch TD with Quote Generation Support".

        Args:
        nonce (bytearray): against replay attacks.
        data (bytearray): user data
        extraArgs: for TPM, it will be given list of IMR/PCRs

        Returns:
            The ``Quote`` object.
        """

        # Prepare user defined data which could include nonce
        if nonce is not None:
            nonce = base64.b64decode(nonce)
        if data is not None:
            data = base64.b64decode(data)
        report_bytes = None
        if self.tdreport is not None:
            LOG.info("Using report data directly to generate quote")
            report_bytes = self.tdreport.data
        if report_bytes is None:
            LOG.error("No existing report data")
            if nonce is None and data is None:
                LOG.info("No report data, generating default quote")
            else:
                LOG.info("Calculate report data by nonce and user data")
                hash_algo = hashlib.sha512()
                if nonce is not None:
                    hash_algo.update(bytes(nonce))
                if data is not None:
                    hash_algo.update(bytes(data))
                report_bytes = hash_algo.digest()

        # Open TDX guest device node
        dev_path = self.DEVICE_NODE_PATH[self.version]
        try:
            tdx_dev = os.open(dev_path, os.O_RDWR)
        except (PermissionError, IOError, OSError) as e:
            LOG.error("Fail to open device node %s: %s", dev_path, str(e))
            return None
        LOG.debug("Successful open device node %s", dev_path)

        # Run ioctl command to get TD Quote
        if self.version is TDX_VERSION_1_0:
            quote_req = TdxQuoteReq10()
        elif self.version is TDX_VERSION_1_5:
            quote_req = TdxQuoteReq15()
        # pylint: disable=E1111
        req_buf = quote_req.prepare_reqbuf(report_bytes)
        try:
            fcntl.ioctl(tdx_dev, self.IOCTL_GET_QUOTE[self.version], req_buf)
        except OSError as e:
            LOG.error("Fail to execute ioctl for file %s: %s", dev_path, str(e))
            os.close(tdx_dev)
            return None
        LOG.debug("Successful get Quote from %s.", dev_path)
        os.close(tdx_dev)

        # Get TD Quote from ioctl command output
        return quote_req.process_output(req_buf)
