
"""
TCG common definitions
"""

class TcgAlgorithmRegistry:
    """
    From TCG specification
    https://trustedcomputinggroup.org/wp-content/uploads/TCG-_Algorithm_Registry_r1p32_pub.pdf
    """

    TPM_ALG_ERROR = 0x0
    TPM_ALG_RSA = 0x1
    TPM_ALG_TDES = 0x3
    TPM_ALG_SHA256 = 0xB
    TPM_ALG_SHA384 = 0xC
    TPM_ALG_SHA512 = 0xD

    TPM_ALG_TABLE = {
        TPM_ALG_RSA: "TPM_ALG_RSA",
        TPM_ALG_TDES: "TPM_ALG_TDES",
        TPM_ALG_SHA256: "TPM_ALG_SHA256",
        TPM_ALG_SHA384: "TPM_ALG_SHA384",
        TPM_ALG_SHA512: "TPM_ALG_SHA512"
    }

    @staticmethod
    def get_algorithm_string(alg_id: int) -> str:
        """
        Return algorithms name from ID
        """
        if alg_id in TcgAlgorithmRegistry.TPM_ALG_TABLE:
            return TcgAlgorithmRegistry.TPM_ALG_TABLE[alg_id]
        return "UNKNOWN"

    def __init__(self, alg_id: int) -> None:
        assert alg_id in TcgAlgorithmRegistry.TPM_ALG_TABLE, \
            "invalid parameter alg_id"
        self._alg_id = alg_id

    @property
    def alg_id(self):
        """
        Property for algorithms ID
        """
        return self._alg_id

    def __str__(self):
        """
        Name string
        """
        return TcgAlgorithmRegistry.get_algorithm_string(self.alg_id)

class TcgDigest:
    """
    TCG Digest
    """

    def __init__(self, alg_id=TcgAlgorithmRegistry.TPM_ALG_SHA384):
        self._hash: list = []
        self._alg_id = alg_id

    @property
    def alg(self) -> TcgAlgorithmRegistry:
        """
        Algorithms for the hash of digest
        """
        return TcgAlgorithmRegistry(self._alg_id)

    @property
    def hash(self) -> list:
        """
        Return the hash of digest
        """
        return self._hash
