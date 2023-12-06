"""
Integrated Measurement Register packages.
"""
from abc import ABC, abstractmethod

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

class TcgDigest:
    """
    TCG Digest
    """

    def __init__(self, alg_id=TcgAlgorithmRegistry.TPM_ALG_SHA384):
        self._algorithms = TcgAlgorithmRegistry(alg_id)
        self._hash = []

    @property
    def algorithms(self) -> TcgAlgorithmRegistry:
        """
        Algorithms for the hash of digest
        """
        return self._algorithms

class TcgIMR(ABC):
    """
    Common Integrated Measurement Register class
    """

    _INVALID_IMR_INDEX = -1

    def __init__(self):
        self._index = -1
        self._digest = []

    @property
    def index(self) -> int:
        """
        The index of IMR register
        """
        return self._index

    @property
    def digest(self):
        """
        The digest value of IMR
        """
        return self._digest

    @property
    @abstractmethod
    def count(self):
        """
        The total account of IMR
        """
        raise NotImplementedError("Need implemented in different arch")

    def is_valid(self):
        """
        Check whether IMR is valid or not
        """
        return self._index != TcgIMR._INVALID_IMR_INDEX and \
            self._index < self.count

class TdxRTMR(TcgIMR):
    """
    RTMR class defined for Intel TDX
    """

    @property
    def count(self):
        return 4

class TpmPCR(TcgIMR):
    """
    PCR class defined for TPM
    """

    @property
    def count(self):
        return 24
