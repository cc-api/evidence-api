"""
Command line to get quote
"""
import argparse
import logging
import cctrusted

LOG = logging.getLogger(__name__)
OUT_FORMAT_RAW = "raw"
OUT_FORMAT_HUMAN = "human"

parser = argparse.ArgumentParser()
parser.add_argument(
    '--out-format',
    action='store',
    help='Output format: raw/human. Default raw.',
    dest='out_format'
)
args = parser.parse_args()

dump_raw = False
f = args.out_format
if f is None:
    # When the format is not set. Dump raw as default.
    dump_raw = True
elif f == OUT_FORMAT_HUMAN:
    dump_raw = False
elif f == OUT_FORMAT_RAW:
    dump_raw = True
else:
    parser.print_help()
    parser.exit(2, "Specified output format is not supported!")

logging.basicConfig(level=logging.NOTSET, format='%(name)s %(levelname)-8s %(message)s')
quote = cctrusted.get_quote(None, None, None)
if quote is not None:
    quote.dump(dump_raw)
