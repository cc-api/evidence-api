"""
TCG compliant Event log
"""

import logging
from cctrusted_base.binaryblob import BinaryBlob
from cctrusted_base.tcg import TcgDigest
from cctrusted_base.tcg import TcgEventType
from cctrusted_base.tcg import TcgEfiSpecIdEvent
from cctrusted_base.tcg import TcgImrEvent
from cctrusted_base.tcg import TcgEfiSpecIdEventAlgorithmSize
from cctrusted_base.tcg import TcgPcClientImrEvent


LOG = logging.getLogger(__name__)

class TcgEventLog:
    """TcgEventLog class.

    This class contains the event logs following TCG specification.

    Attributes:
        data: raw data containing all boot time event logs
        event_logs: all parsed event logs
        count: total number of event logs
    """
    spec_id_header_event = None

    def __init__(self, data:bytes) -> None:
        self._data = data
        self._event_logs = []
        self._count:int = 0

    @property
    def data(self):
        """Raw data of TCG event logs."""
        return self._data

    @property
    def event_logs(self):
        """Parsed event logs."""
        return self._event_logs

    @property
    def count(self):
        """Total number of event logs."""
        return self._count

    def dump(self, is_raw=True) -> None:
        """Dump event log data.

        Args:
            is_raw: indicator for dump output format
                True: dump in hex strings
                False: dump in human readable texts
        """
        if self._count == 0:
            LOG.info("No parsed event log found.")
            return

        if is_raw:
            LOG.info("RAW DATA: ------------------------------------------------------------------")
            blob = BinaryBlob(self._data, 0)
            blob.dump()
            LOG.info("RAW DATA: ------------------------------------------------------------------")
            return

        LOG.info("Event Log Entries:")
        for event in self._event_logs:
            event.dump()

    def select(self, start:int, count:int) -> None:
        """Collect selected event logs according to user input.

        Args:
            start: index of the first event log to collect
            count: total number of event logs to collect
        """
        self._parse()

        if start is not None:
            if not 0 < start <= self._count:
                # pylint: disable-next=line-too-long
                LOG.error("Invalid input start. Start must be number larger than 0 and smaller than total event log count.")
                raise ValueError('Invalid parameter start.')

            self._event_logs = self._event_logs[start-1:]

        if count is not None:
            if not 0 < count <= len(self._event_logs):
                # pylint: disable-next=line-too-long
                LOG.error("Invalid input count. count must be number larger than 0 and smaller than total event log count.")
                raise ValueError('Invalid parameter count.')

            self._event_logs = self._event_logs[:count]

    def _parse(self) -> None:
        """Parse event log data into TCG compatible forms.

        Run through all event log data and parse the contents accordingly
        Save the parsed event logs into TcgEventLog.
        """
        if self._data is None:
            LOG.error("Providing invalid data blob.")

        blob = BinaryBlob(self._data, 0)
        index = 0

        while index < len(self._data):
            start = index
            imr, index = blob.get_uint32(index)
            event_type, index = blob.get_uint32(index)

            if imr == 0xFFFFFFFF:
                break

            if event_type == TcgEventType.EV_NO_ACTION:
                spec_id_event, event_len = \
                    self._parse_spec_id_event_log(self._data[start:])
                index = start + event_len
                self._event_logs.append(spec_id_event)
                self._count += 1
            else:
                event_log, event_len = self._parse_event_log(self._data[start:])
                index = start + event_len
                self._event_logs.append(event_log)
                self._count += 1

    def _parse_spec_id_event_log(self, data:bytes) -> (TcgPcClientImrEvent, int):
        """Parse TCG specification Id event according to TCG spec at
        https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf.

        Event Structure:
        typedef tdTCG_PCClientPCREvent {
            2735 UINT32 pcrIndex;
            UINT32 eventType;
            BYTE digest[20];
            UINT32 eventDataSize;
            BYTE event[eventDataSize]; //This is actually a TCG_EfiSpecIDEventStruct
        } TCG_PCClientPCREvent;

        Args:
            data: event log data in bytes

        Returns:
            A TcgPcClientImrEvent containing the Specification ID version event
            An int specifying the event size
        """
        index = 0

        blob = BinaryBlob(data, 0)

        imr_index, index = blob.get_uint32(index)
        header_imr = imr_index - 1
        header_event_type, index = blob.get_uint32(index)

        digest, index = blob.get_bytes(index, 20)  # 20 zero for digest
        header_event_size, index = blob.get_uint32(index) # 4 bytes containing event size
        header_event, _ = blob.get_bytes(index, header_event_size)

        specification_id_header = TcgPcClientImrEvent(header_imr, header_event_type, digest,
                                                   header_event_size, header_event)

        # Parse EFI Spec Id Event structure
        spec_id_signature, index = blob.get_bytes(index, 16)
        spec_id_platform_cls, index = blob.get_uint32(index)
        spec_id_version_minor, index = blob.get_uint8(index)
        spec_id_version_major, index = blob.get_uint8(index)
        spec_id_errata, index = blob.get_uint8(index)
        spec_id_uint_size, index = blob.get_uint8(index)
        spec_id_num_of_algo, index = blob.get_uint32(index)
        spec_id_digest_sizes = []
        for _ in range(spec_id_num_of_algo):
            algo_id, index = blob.get_uint16(index)
            digest_size, index = blob.get_uint16(index)
            spec_id_digest_sizes.append(TcgEfiSpecIdEventAlgorithmSize(algo_id, digest_size))
        spec_id_vendor_size, index = blob.get_uint8(index)
        if spec_id_vendor_size > 0:
            spec_id_vendor_info, index = blob.get_bytes(index, int(spec_id_vendor_size))
        else:
            spec_id_vendor_info = bytes()
        TcgEventLog.spec_id_header_event = \
            TcgEfiSpecIdEvent(spec_id_signature, spec_id_platform_cls,
                              spec_id_version_minor, spec_id_version_major,
                              spec_id_errata, spec_id_uint_size, spec_id_num_of_algo,
                              spec_id_digest_sizes, spec_id_vendor_size,
                              spec_id_vendor_info)

        return specification_id_header, index

    def _parse_event_log(self, data:bytes) -> (TcgImrEvent, int):
        """Parse TCG event log body as single event log entry (TcgImrEventLogEntry) defined at
        https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf

        typedef struct tdTCG_PCR_EVENT2{
            UINT32 pcrIndex;
            UINT32 eventType;
            TPML_DIGEST_VALUES digests;
            UINT32 eventSize;
            BYTE event[eventSize];
        } TCG_PCR_EVENT2;

        Args:
            data: event log data in bytes

        Returns:
            A TcgImrEvent containing the event information
            An int specifying the event size
        """
        index = 0

        blob = BinaryBlob(data, 0)

        imr_index, index = blob.get_uint32(index)
        imr_index = imr_index - 1
        event_type, index = blob.get_uint32(index)

        # Fetch digest count and get each digest and its algorithm
        digest_count, index = blob.get_uint32(index)
        digests = []
        for _ in range(digest_count):
            alg_id, index = blob.get_uint16(index)
            alg = next((alg for alg in \
                        TcgEventLog.spec_id_header_event.digest_sizes \
                        if alg.algo_id == alg_id), None)
            if alg is None:
                raise ValueError(f'No algorithm with such algo_id {alg_id} found')
            digest_size = alg.digest_size
            digest_data, index = blob.get_bytes(index, digest_size)
            digest = TcgDigest(alg_id, digest_data)
            digests.append(digest)
        event_size, index = blob.get_uint32(index)
        event, index = blob.get_bytes(index, event_size)

        # Generate TcgImrEvent using the info parsed
        entry = TcgImrEvent(imr_index, event_type, digests, event_size,
                                    event)
        return entry, index
