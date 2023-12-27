"""
Command line to dump the cc event logs
"""
import logging
import argparse
from cctrusted_vm import CCTrustedVmSdk


LOG = logging.getLogger(__name__)

logging.basicConfig(level=logging.NOTSET, format='%(message)s')

def main():
    """example cc event log fetching utility"""
    parser = argparse.ArgumentParser(
        description="The example utility to fetch CC event logs")
    parser.add_argument('-s', type=int,
                        help='index of first event log to fetch', dest='start')
    parser.add_argument("-c", type=int, help="number of event logs to fetch",
                        dest="count")
    parser.add_argument("--out-format-raw", default=True,
                        dest="out_format",
                        help="output format. Return raw when set as True.\
                              Return parsed info when set as False.",
                        type=lambda x: (str(x).lower() in ['true','1', 'yes']))
    args = parser.parse_args()

    event_logs = CCTrustedVmSdk.inst().get_eventlog(args.start, args.count)
    if event_logs is not None:
        LOG.info("Total %d of event logs fetched.", len(event_logs.event_logs))
        event_logs.dump(args.out_format)

if __name__ == "__main__":
    main()
