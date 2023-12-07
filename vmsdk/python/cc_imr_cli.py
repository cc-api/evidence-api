
"""
Command line to dump the integrated measurement register
"""
import logging
import cctrusted

LOG = logging.getLogger(__name__)

logging.basicConfig(level=logging.NOTSET, format='%(name)s %(levelname)-8s %(message)s')

imr_inst = cctrusted.get_measurement([2, None])

# TODO: print IMR
