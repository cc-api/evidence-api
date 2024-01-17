"""
RTMR (Runtime Measurement Register).
"""

from cctrusted_base.imr import TcgIMR
from cctrusted_base.tcg import TcgAlgorithmRegistry

class TdxRTMR(TcgIMR):
    """RTMR class defined for Intel TDX."""

    RTMR_COUNT = 4
    """Intel TDX TDREPORT provides the 4 measurement registers by default."""

    RTMR_LENGTH_BY_BYTES = 48
    """RTMR length by bytes."""

    @property
    def max_index(self):
        return 3

    def __init__(self, index, digest_hash):
        super().__init__(index, TcgAlgorithmRegistry.TPM_ALG_SHA384,
                        digest_hash)
