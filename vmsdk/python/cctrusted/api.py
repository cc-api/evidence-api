"""
CC Trusted API Implementation.
"""
import logging

# pylint: disable=unused-import
from cctrusted_base.imr import TcgIMR
from .cc_linux import CcLinuxStub

LOG = logging.getLogger(__name__)

def get_measurement(imr_select_index:int) -> TcgIMR:
    """
    Get IMR register value according to given index
    """
    cc_linux_inst = CcLinuxStub.inst()
    if imr_select_index > len(cc_linux_inst.imrs):
        LOG.error("Invalid select index for IMR.")
        return None

    return cc_linux_inst.imrs[imr_select_index]
