
"""
Command line to dump the integrated measurement register
"""
import logging
import cctrusted

LOG = logging.getLogger(__name__)

logging.basicConfig(level=logging.NOTSET)

imr_inst = cctrusted.get_measurement([2, None])

# TODO: print IMR
