"""
API implementation for TDX specific
"""
import logging

from cctrusted_base.tdx.report import TdReport
from .cvm import ConfidentialVM, TdxVM

LOG = logging.getLogger(__name__)

def get_tdx_report() -> TdReport:
    """
    Get TDX Report
    """
    cvm_inst = ConfidentialVM.inst()
    cvm_inst.dump()

    assert isinstance(cvm_inst, TdxVM)
    return cvm_inst.tdreport
