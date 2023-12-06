import sys
sys.path.append("../..")

from vmsdk.python.cctrusted.eventlog import Eventlog

eventlog = Eventlog.get_eventlog()

eventlog.dump_td_event_log_by_index(89)
