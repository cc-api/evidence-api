"""
The VMSDK implementation for ``CCTrusted`` API.
"""
import logging

# pylint: disable=unused-import
from cctrusted_base.api import CCTrustedApi
from cctrusted_base.imr import TcgIMR
from cctrusted_base.ccreport import CcReport
from cctrusted_base.eventlog import EventLogs
from cctrusted_base.eventlog import TcgEventLog
from cctrusted_base.tcg import TcgAlgorithmRegistry
from cctrusted_vm.cvm import ConfidentialVM


LOG = logging.getLogger(__name__)

class CCTrustedVmSdk(CCTrustedApi):

    """CC trusted API implementation for a general CVM."""

    _inst = None

    @classmethod
    def inst(cls):
        """Singleton instance function."""
        if cls._inst is None:
            cls._inst = cls()
        return cls._inst

    def __init__(self):
        """Contrustor of CCTrustedCVM."""
        self._cvm = ConfidentialVM.inst()

    def get_default_algorithms(self) -> TcgAlgorithmRegistry:
        """Get the default Digest algorithms supported by trusted foundation.

        Different trusted foundation may support different algorithms, for example
        the Intel TDX use SHA384, TPM uses SHA256.

        Beyond the default digest algorithm, some trusted foundation like TPM
        may support multiple algorithms.

        Returns:
            The default algorithms.
        """
        return TcgAlgorithmRegistry(self._cvm.default_algo_id)

    def get_measurement_count(self) -> int:
        """Get the count of measurement register.

        Different trusted foundation may provide different count of measurement
        register. For example, Intel TDX TDREPORT provides the 4 measurement
        register by default. TPM provides 24 measurement (0~16 for SRTM and 17~24
        for DRTM).

        Beyond the real mesurement register, some SDK may extend virtual measurement
        reigster for additional trust chain like container, namespace, cluster in
        cloud native paradiagm.

        Returns:
            The count of measurement registers
        """
        return len(self._cvm.imrs)

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
        imr_index = imr_select[0]
        algo_id = imr_select[1]

        if imr_index not in self._cvm.imrs:
            LOG.error("Invalid select index for IMR.")
            return None

        if algo_id is None or algo_id is TcgAlgorithmRegistry.TPM_ALG_ERROR:
            algo_id = self._cvm.default_algo_id

        # Re-do the processing to fetch the latest measurements
        self._cvm.process_cc_report()

        return self._cvm.imrs[imr_index]

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
        return self._cvm.get_cc_report(nonce, data, extraArgs)

    def get_cc_eventlog(self, start:int = None, count:int = None) -> EventLogs:
        """Get eventlog for given index and count.

        TCG log in Eventlog. Verify to spoof events in the TCG log, hence defeating
        remotely-attested measured-boot.
        To measure the full CC runtime environment, the eventlog may include addtional
        OS type and cloud native type event beyond the measured-boot.

        Args:
            start(int): the first index of event log to fetch
            count(int): the number of event logs to fetch

        Returns:
            ``Eventlogs`` object containing all event logs following TCG PCClient Spec.
        """
        # Re-do the processing to fetch the latest event logs
        self._cvm.process_eventlog()

        event_logs = EventLogs(self._cvm.boot_time_event_log, self._cvm.runtime_event_log,
                               TcgEventLog.TCG_PCCLIENT_FORMAT)

        event_logs.select(start, count)

        return event_logs

    def replay_cc_eventlog(self, event_logs:EventLogs) -> dict:
        """Replay event logs based on data provided.

        TCG event logs can be replayed against IMR measurements to prove the integrity of
        the event logs.

        Args:
            event_logs(Eventlogs): the ``Eventlogs`` object to replay

        Returns:
            A dictionary containing the replay result displayed by IMR index and hash algorithm. 
            Layer 1 key of the dict is the IMR index, the value is another dict which using the
            hash algorithm as the key and the replayed measurement as value.
            Sample value:
                { 0: { 12: <measurement_replayed>}}
        """
        replay_res = event_logs.replay()

        return replay_res
