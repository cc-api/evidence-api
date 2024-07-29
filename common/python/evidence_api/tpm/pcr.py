"""
PCR (Platform Configuration Register).
"""

from evidence_api.imr import TcgIMR
from evidence_api.tcg import TcgAlgorithmRegistry

class TpmPCR(TcgIMR):
    """PCR class defined for TPM"""

    @property
    def max_index(self):
        return 23

    def __init__(self, index, digest_hash):
        super().__init__(index, TcgAlgorithmRegistry.TPM_ALG_SHA256,
                        digest_hash)
