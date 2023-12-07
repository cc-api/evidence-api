"""
CC Trusted API Implementation.
"""
import logging

# pylint: disable=unused-import
from cctrusted_base.imr import TcgIMR
from cctrusted_base.tcg import TcgAlgorithmRegistry

from .cvm import ConfidentialVM

LOG = logging.getLogger(__name__)

def get_measurement(imr_select:[int, int]) -> TcgIMR:
    """
    Get IMR register value according to given index
    """
    cvm_inst = ConfidentialVM.inst()
    imr_index = imr_select[0]
    algo_id = imr_select[1]

    if imr_index not in cvm_inst.imrs:
        LOG.error("Invalid select index for IMR.")
        return None

    if algo_id is None or algo_id is TcgAlgorithmRegistry.TPM_ALG_ERROR:
        algo_id = cvm_inst.default_algo_id

    return cvm_inst.imrs[imr_index].digest(algo_id)
