"""
The CC stub in Linux.

If it is device node, it can be /dev/tdx-guest or /dev/sev-guest
If also can be sysfs
"""
import logging
from abc import ABC, abstractmethod
from cctrusted_base.imr import TcgIMR

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

class CcLinuxStub:

    TYPE_CC_NONE = -1
    TYPE_CC_TDX = 0
    TYPE_CC_SEV = 1
    TYPE_CC_CCA = 1

    _inst = None

    def __init__(self):
        self._device_node:CcDeviceNode = None
        self._cc_type:int = CcLinuxStub.TYPE_CC_NONE
        self._is_init:bool = False
        self._imrs:list[TcgIMR] = []

    @property
    def cc_type(self) -> int:
        """
        CC type like TYPE_CC_TDX, TYPE_CC_SEV etc
        """
        return self._cc_type

    @property
    def imrs(self):
        """
        The array of integrated measurement registers (IMR)
        """
        return self._imrs

    def init(self):
        """
        Initialize the CC stub and environment
        """
        if self._cc_type is not CcLinuxStub.TYPE_CC_NONE:
            return True

        cc_type = self._detect_cc_type()
        if not self._process_device_node():
            return False
        self._cc_type = cc_type
        return True

    def _detect_cc_type(self):
        # TODO: add code to detect CC type
        LOG.info("Detect the CC type")
        return CcLinuxStub.TYPE_CC_NONE

    def _process_device_node(self):
        # TODO: add code to process device node
        return True

    @staticmethod
    def inst():
        """
        Singleton interface for the instance of CcLinuxStub
        """
        if CcLinuxStub._inst is None:
            inst = CcLinuxStub()
            if inst.init():
                CcLinuxStub._inst = inst
        return CcLinuxStub._inst
