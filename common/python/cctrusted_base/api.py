"""
The CC Trusted API
"""
import logging
from abc import ABC, abstractmethod
# pylint: disable=unused-import
from cctrusted_base.imr import TcgIMR
from cctrusted_base.eventlog import EventLogs
from cctrusted_base.ccreport import CcReport
from cctrusted_base.tcg import TcgAlgorithmRegistry

LOG = logging.getLogger(__name__)

class CCTrustedApi(ABC):

    """Abstract class for CC Trusted API.

    The inherited SDK class will implement the APIs.
    """

    TYPE_CC_NONE = -1
    TYPE_CC_TPM = 0
    TYPE_CC_TDX = 1
    TYPE_CC_SEV = 2
    TYPE_CC_CCA = 3

    TYPE_CC_STRING = {
        TYPE_CC_TPM: "TPM",
        TYPE_CC_TDX: "TDX",
        TYPE_CC_SEV: "SEV",
        TYPE_CC_CCA: "CCA"
    }

    @staticmethod
    def cc_type_str(cc_type):
        """the CC type string."""
        return CCTrustedApi.TYPE_CC_STRING[cc_type]

    @abstractmethod
    def get_default_algorithms(self) -> TcgAlgorithmRegistry:
        """Get the default Digest algorithms supported by trusted foundation.

        Different trusted foundation may support different algorithms, for example
        the Intel TDX use SHA384, TPM uses SHA256.

        Beyond the default digest algorithm, some trusted foundation like TPM
        may support multiple algorithms.

        Returns:
            The default algorithms.
        """
        raise NotImplementedError("Inherited SDK class should implement this.")

    @abstractmethod
    def get_measurement_count(self) -> int:
        """Get the count of measurement register.

        Different trusted foundation may provide different count of measurement
        register. For example, Intel TDX TDREPORT provides the 4 measurement
        register by default. TPM provides 24 measurement (0~16 for SRTM and 17~24
        for DRTM).

        Beyond the real mesurement register, some SDK may extend virtual measurement
        reigster for addtional trust chain like container, namespace, cluster in
        cloud native paradiagm.

        Returns:
            The count of measurement registers
        """
        raise NotImplementedError("Inherited SDK class should implement this.")

    @abstractmethod
    def get_cc_measurement(self, imr_select:[int, int]) -> TcgIMR:
        """Get measurement register according to given selected index and algorithms

        Each trusted foundation in CC environment provides the multiple measurement
        registers, the count is update to ``get_measurement_count()``. And for each
        measurement register, it may provides multiple digest for different algorithms.

        Args:
            imr_select ([int, int]): The first is index of measurement register,
                the second is the alrogithms ID

        Returns:
            The object of TcgIMR
        """
        raise NotImplementedError("Inherited SDK class should implement this.")

    @abstractmethod
    def get_cc_report(
        self,
        nonce: bytearray = None,
        data: bytearray = None,
        extraArgs = None
    ) -> CcReport:
        """Get the quote for given nonce and data.

        The quote is signing of attestation data (IMR values or hashes of IMR
        values), made by a trusted foundation (TPM) using a key trusted by the
        verifier.

        Different trusted foundation may use different quote format.

        Args:
            nonce (bytearray): against replay attacks.
            data (bytearray): user data
            extraArgs: for TPM, it will be given list of IMR/PCRs

        Returns:
            The ``Quote`` object.
        """
        raise NotImplementedError("Inherited SDK class should implement this.")

    @abstractmethod
    def get_cc_eventlog(self, start:int = None, count:int = None) -> list:
        """Get eventlog for given index and count.

        TCG log in Eventlog. Verify to spoof events in the TCG log, hence defeating
        remotely-attested measured-boot.
        To measure the full CC runtime environment, the eventlog may include addtional
        OS type and cloud native type event beyond the measured-boot.

        Args:
            start(int): the first index of event log to fetch
            count(int): the number of event logs to fetch

        Returns:
            list of parsed event logs following TCG spec.
        """
        raise NotImplementedError("Inherited SDK class should implement this.")

    @staticmethod
    def replay_cc_eventlog(event_logs:list) -> dict:
        """Replay event logs based on data provided.

        TCG event logs can be replayed against IMR measurements to prove the integrity of
        the event logs.

        Args:
            event_logs(list): the list of parsed event logs to replay

        Returns:
            A dictionary containing the replay result displayed by IMR index and hash algorithm.
            Layer 1 key of the dict is the IMR index, the value is another dict which using the
            hash algorithm as the key and the replayed measurement as value.
            Sample value:
                { 0: { 12: <measurement_replayed> } }
        """
        if event_logs is None or len(event_logs) == 0:
            LOG.info("No event log provided to replay.")
            return {}

        return EventLogs.replay(event_logs)
