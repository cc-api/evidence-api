"""
Command line to get quote
"""
import logging
import cctrusted

LOG = logging.getLogger(__name__)

logging.basicConfig(level=logging.NOTSET, format='%(name)s %(levelname)-8s %(message)s')

cctrusted.get_quote(None, None, None)
