"""
Confidential VM class manages following items:

1. Confidential device node like /dev/tdx-guest or /dev/sev-guest
2. Event log table from memory
3. IMR (integrated measurement register)

"""

import logging
from abc import ABC, abstractmethod
from cctrusted_base.imr import TcgIMR
from cctrusted_base.tcg import TcgAlgorithmRegistry

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

    _inst = None

    def __init__(self):
        self._device_node:CcDeviceNode = None
        self._cc_type:int = ConfidentialVM.TYPE_CC_NONE
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
    def imrs(self) -> list[TcgIMR]:
        """
        The array of integrated measurement registers (IMR)
        """
        return self._imrs

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
        # TODO: add code to detect CC type
        LOG.info("Detect the CC type")
        return ConfidentialVM.TYPE_CC_TDX

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

    def process_cc_report(self):
        """
        Process the confidential computing REPORT.
        """
        return True

    def process_eventlog(self):
        """
        Process the event log
        """
        return True

    @property
    def default_algo_id(self):
        return TcgAlgorithmRegistry.TPM_ALG_SHA384
