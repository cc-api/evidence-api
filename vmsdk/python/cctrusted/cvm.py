"""
Confidential VM class manages following items:

1. Confidential device node like /dev/tdx-guest or /dev/sev-guest
2. Event log table from memory
3. IMR (integrated measurement register)

"""
import os
import logging
import struct
import fcntl
from abc import ABC, abstractmethod
from cctrusted_base.imr import TdxRTMR,TcgIMR
from cctrusted_base.tcg import TcgAlgorithmRegistry
from cctrusted_base.tdx.common import TDX_VERSION_1_0, TDX_VERSION_1_5
from cctrusted_base.tdx.report import TdxReportReq10, TdxReportReq15

LOG = logging.getLogger(__name__)

class CcDeviceNode(ABC):

    @property
    @abstractmethod
    def device_node_path(self) -> str:
        """
        Return the name of device node
        """
        raise NotImplementedError("Need implement in inherited class")

class TdxDeviceNode(CcDeviceNode):

    DEVICE_NODE_NAME_1_0 = "/dev/tdx-guest"
    DEVICE_NODE_NAME_1_5 = "/dev/tdx_guest"

    @property
    def device_node_path(self) -> str:
        return TdxDeviceNode.DEVICE_NODE_NAME_1_5

class ConfidentialVM:

    TYPE_CC_NONE = -1
    TYPE_CC_TDX = 0
    TYPE_CC_SEV = 1
    TYPE_CC_CCA = 1

    TYPE_CC_STRING = {
        TYPE_CC_TDX: "TDX",
        TYPE_CC_SEV: "SEV",
        TYPE_CC_CCA: "CCA"
    }

    _inst = None

    def __init__(self, cctype):
        self._device_node:CcDeviceNode = None
        self._cc_type:int = cctype
        self._is_init:bool = False
        self._imrs:dict[int, TcgIMR] = {}

    @property
    def cc_type(self) -> int:
        """
        CC type like TYPE_CC_TDX, TYPE_CC_SEV etc
        """
        return self._cc_type

    @property
    @abstractmethod
    def default_algo_id(self):
        """
        Default algorithms ID supported by this Confidential VM
        """
        raise NotImplementedError("Should be implemented by inherited class")

    @property
    @abstractmethod
    def version(self):
        """
        Version of CC VM
        """
        raise NotImplementedError("Should be implemented by inherited class")

    @property
    def imrs(self) -> list[TcgIMR]:
        """
        The array of integrated measurement registers (IMR)
        """
        return self._imrs

    @property
    def cc_type_str(self):
        """
        Return the CC type string
        """
        return ConfidentialVM.TYPE_CC_STRING[self.cc_type]

    def init(self) -> bool:
        """
        Initialize the CC stub and environment
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
        """
        Detect the type of current confidential VM
        """
        # TODO: refine the justification
        for devpath in TdxVM.DEVICE_NODE_PATH.values():
            if os.path.exists(devpath):
                return ConfidentialVM.TYPE_CC_TDX
        return ConfidentialVM.TYPE_CC_NONE

    @abstractmethod
    def process_cc_report(self):
        """
        Process the confidential computing REPORT.
        """
        raise NotImplementedError("Should be implemented by inherited class")

    @abstractmethod
    def process_eventlog(self):
        """
        Process the event log
        """
        raise NotImplementedError("Should be implemented by inherited class")

    def dump(self):
        """
        Dump confidential VM information
        """
        LOG.info("======================================")
        LOG.info("CVM type = %s", self.cc_type_str)
        LOG.info("CVM version = %s", self.version)
        LOG.info("======================================")

    @staticmethod
    def inst():
        """
        Singleton interface for the instance of CcLinuxStub
        """
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
        """
        return TDREPORT structure
        """
        return self._tdreport

    def process_cc_report(self) -> bool:
        """
        Process the confidential computing REPORT.
        """
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
        """
        Process the event log
        """
        return True
