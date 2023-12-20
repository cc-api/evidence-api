"""
Command line to dump the cc event logs
"""
import logging
from cctrusted import CCTrustedVmSdk

LOG = logging.getLogger(__name__)

logging.basicConfig(level=logging.NOTSET, format='%(message)s')

event_logs = CCTrustedVmSdk.inst().get_eventlog()
LOG.info("Total %d of event logs fetched.", len(event_logs.event_logs))
event_logs.spec_id_header.dump()
for e in event_logs.event_logs:
    e.dump()
