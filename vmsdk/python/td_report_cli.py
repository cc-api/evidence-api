
"""
Command line to dump the integrated measurement register
"""
import logging
import cctrusted

LOG = logging.getLogger(__name__)

logging.basicConfig(level=logging.NOTSET, format='%(message)s')

tdreport = cctrusted.get_tdx_report()
tdreport.dump()
