
"""
Command line to dump the integrated measurement register
"""
import logging
import cctrusted

LOG = logging.getLogger(__name__)

logging.basicConfig(level=logging.NOTSET, format='%(name)s %(levelname)-8s %(message)s')

count = cctrusted.get_measurement_count()
for index in range(cctrusted.get_measurement_count()):
    alg = cctrusted.get_default_algorithms()
    digest_obj = cctrusted.get_measurement([index, alg.alg_id])

    hash_str = ""
    for hash_item in digest_obj.hash:
        hash_str += "".join([f"{hash_item:02x}", " "])

    LOG.info("Algorithms: %s", str(alg))
    LOG.info("HASH: %s", hash_str)
