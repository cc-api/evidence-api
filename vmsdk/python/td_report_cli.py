
"""
Command line to dump the integrated measurement register
"""
import logging
from cctrusted_vm import CCTrustedTdvmSdk

LOG = logging.getLogger(__name__)

logging.basicConfig(level=logging.NOTSET, format='%(message)s')

tdreport = CCTrustedTdvmSdk.inst().get_tdreport()
tdreport.dump()
