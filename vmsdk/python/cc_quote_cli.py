"""
Command line to get quote
"""
import argparse
import logging
from cctrusted import CCTrustedVmSdk

LOG = logging.getLogger(__name__)
OUT_FORMAT_RAW = "raw"
OUT_FORMAT_HUMAN = "human"

def out_format_validator(out_format):
    """Validator (callback for ArgumentParser) of output format

    Args:
        out_format: User specified output format.

    Returns:
        Validated value of the argument.

    Raises:
        ValueError: An invalid value is given by user.
    """
    if out_format not in (OUT_FORMAT_HUMAN, OUT_FORMAT_RAW):
        raise ValueError
    return out_format

def main():
    """Example to call get_quote and dump the result to stdout"""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--out-format",
        action="store",
        default=OUT_FORMAT_RAW,
        dest="out_format",
        help="Output format: raw/human. Default raw.",
        type=out_format_validator
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.NOTSET,
        format="%(name)s %(levelname)-8s %(message)s"
    )
    quote = CCTrustedVmSdk.inst().get_quote(None, None, None)
    if quote is not None:
        quote.dump(args.out_format == OUT_FORMAT_RAW)

if __name__ == "__main__":
    main()
