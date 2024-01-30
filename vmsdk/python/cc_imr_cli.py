
"""
Command line to dump the integrated measurement register
"""
import logging
import os
from cctrusted_base.api import CCTrustedApi
from cctrusted_vm.cvm import ConfidentialVM
from cctrusted_vm.sdk import CCTrustedVmSdk

LOG = logging.getLogger(__name__)

logging.basicConfig(level=logging.NOTSET, format='%(name)s %(levelname)-8s %(message)s')

def main():
    """Example to call get_cc_measurement and dump the result to stdout."""
    if ConfidentialVM.detect_cc_type() == CCTrustedApi.TYPE_CC_NONE:
        LOG.error("This is not a confidential VM!")
        return
    if os.geteuid() != 0:
        LOG.error("Please run as root which is required for this example!")
        return

    count = CCTrustedVmSdk.inst().get_measurement_count()
    LOG.info("Measurement Count: %d", count)
    for index in range(CCTrustedVmSdk.inst().get_measurement_count()):
        alg = CCTrustedVmSdk.inst().get_default_algorithms()
        imr = CCTrustedVmSdk.inst().get_cc_measurement([index, alg.alg_id])
        digest_obj = imr.digest(alg.alg_id)

        hash_str = ""
        for hash_item in digest_obj.hash:
            hash_str += "".join([f"{hash_item:02x}", " "])

        LOG.info("Algorithms: %s", str(alg))
        LOG.info("HASH: %s", hash_str)

if __name__ == "__main__":
    main()
