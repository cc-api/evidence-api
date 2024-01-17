"""
PCR (Platform Configuration Register).
"""

from cctrusted_base.imr import TcgIMR

class TpmPCR(TcgIMR):
    """PCR class defined for TPM"""

    @property
    def max_index(self):
        return 23
