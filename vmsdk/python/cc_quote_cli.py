"""
Command line to get quote
"""
import argparse
import base64
import logging
import random
from cctrusted_vm import CCTrustedVmSdk

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

def make_nounce():
    """Make nonce for demo.

    Returns:
        A nonce for demo that is base64 encoded bytes reprensting a 64 bits unsigned integer.
    """
    # Generte a 64 bits unsigned integer randomly (range from 0 to 64 bits max).
    rand_num = random.randrange(0x0, 0xFFFFFFFFFFFFFFFF, 1)
    nonce = base64.b64encode(rand_num.to_bytes(8, "little"))
    return nonce

def make_userdata():
    """Make userdata for demo.

    Returns:
        User data that is base64 encoded bytes for demo.
    """
    userdata = base64.b64encode(bytes("demo user data", "utf-8"))
    return userdata

def main():
    """Example to call get_quote and dump the result to stdout."""
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

    nonce = make_nounce()
    LOG.info("demo random number in base64: %s", nonce.decode("utf-8"))
    userdata = make_userdata()
    LOG.info("demo user data in base64: %s", userdata.decode("utf-8"))

    quote = CCTrustedVmSdk.inst().get_quote(nonce, userdata)
    if quote is not None:
        quote.dump(args.out_format == OUT_FORMAT_RAW)
    else:
        LOG.error("Fail to get Quote!")
        LOG.error("Please double check the log and your config!")

if __name__ == "__main__":
    main()
