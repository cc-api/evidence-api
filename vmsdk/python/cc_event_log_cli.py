"""
Command line to dump the cc event logs
"""
import logging
import cctrusted

LOG = logging.getLogger(__name__)

logging.basicConfig(level=logging.NOTSET, format='%(message)s')

event_logs = cctrusted.get_eventlog()
LOG.info("Total %d of event logs fetched.", len(event_logs.event_logs))
for e in event_logs.event_logs:
    e.dump()
