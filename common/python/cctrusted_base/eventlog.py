"""
TCG compliant Event log
"""

import logging
from cctrusted_base.binaryblob import BinaryBlob
from cctrusted_base.tcg import TcgDigest
from cctrusted_base.tcg import TcgEventType
from cctrusted_base.tcg import TcgEfiSpecIdEvent
from cctrusted_base.tcg import TcgImrEventLogEntry
from cctrusted_base.tcg import TcgEfiSpecIdEventAlgorithmSize
from cctrusted_base.tcg import TcgPcClientImrEvent


LOG = logging.getLogger(__name__)

class TcgEventLog:

    def __init__(self, data:bytes) -> None:
        self._data = data
        self._spec_id_header:TcgPcClientImrEvent = None
        self._spec_id_header_event:TcgEfiSpecIdEvent = None
        self._event_logs:list[TcgImrEventLogEntry] = []
        self._count:int = 0

    @property
    def data(self):
        """
        Return raw data of TCG event logs
        """
        return self._data

    @property
    def spec_id_header(self):
        """
        Return the Specification ID Version Event
        """
        return self._spec_id_header

    @property
    def event_logs(self):
        """
        Return event logs except
        the Specification ID Version Event
        """
        return self._event_logs

    @property
    def count(self):
        """
        Return number of event logs except header
        """
        return self._count

    def dump_raw(self):
        """
        Dump raw event log data
        """
        LOG.info("RAW DATA: ----------------------------------------------")
        blob = BinaryBlob(self._data, 0)
        blob.dump()
        LOG.info("RAW DATA: ----------------------------------------------")

    def dump(self):
        """
        Dump formatted event log data
        """
        if self._count == 0:
            LOG.info("No parsed event log found.")
            return

        LOG.info("Total %d of event logs found.", self._count)
        LOG.info("EVENT LOG HEADER DATA:--------------------------------------------")
        LOG.info("Header IMR: %d", self._spec_id_header.imr_index)
        LOG.info("Header Event Type: %s",
                TcgEventType.get_event_type_string(self._spec_id_header.event_type))
        LOG.info("Header Event: ")
        # add specification id event dump
        LOG.info("EVENT LOG DATA:---------------------------------------------------")
        # add the event log dump

    def select(self, start:int, count:int, start_addr:int, log_len:int) -> None:
        """
        Select number of event logs to be returned
        """
        self._parse(start_addr, log_len)

        if start is not None:
            if not 0 < start <= self._count:
                LOG.error("Invalid input start. Start must be number larger than 0 \
                      and smaller than total event log count.")
            else:
                self._event_logs = self._event_logs[start-1:]

        if count is not None:
            if not 0 < count <= len(self._event_logs):
                LOG.error("Invalid input count. count must be number larger than 0 \
                      and smaller than total event log count.")
            else:
                self._event_logs = self._event_logs[:count-1]

    def _parse(self, start_addr:int, log_len:int) -> None:
        """
        Parse TCG event logs
        """
        if self._data is None or start_addr is None:
            LOG.error("Providing invalid data blob and start address")

        blob = BinaryBlob(self._data, start_addr)
        index = 0

        while index < log_len:
            start = index
            imr, index = blob.get_uint32(index)
            event_type, index = blob.get_uint32(index)

            if imr == 0xFFFFFFFF:
                break

            if event_type == TcgEventType.EV_NO_ACTION:
                header_len = self._parse_header(self._data[start:], start_addr)
                index = start + header_len
            else:
                event_log, e_len = self._parse_event_log_body(self._data[start:], start_addr)
                index = start + e_len
                self._event_logs.append(event_log)
                self._count += 1

    def _parse_header(self, data:bytes, start_addr:int) -> int:
        """
        Parse TCG special Id event according to TCG spec at
        https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf

        typedef tdTCG_PCClientPCREvent {
            2735 UINT32 pcrIndex;
            UINT32 eventType;
            BYTE digest[20];
            UINT32 eventDataSize;
            BYTE event[eventDataSize]; //This is actually a TCG_EfiSpecIDEventStruct
        } TCG_PCClientPCREvent;
        """
        index = 0

        blob = BinaryBlob(data, start_addr)

        imr_index, index = blob.get_uint32(index)
        header_imr = imr_index - 1
        header_event_type, index = blob.get_uint32(index)

        digest, index = blob.get_bytes(index, 20)  # 20 zero for digest
        header_event_size, index = blob.get_uint32(index) # 4 bytes containing event size
        header_event, _ = blob.get_bytes(index, header_event_size)

        self._spec_id_header = TcgPcClientImrEvent(header_imr, header_event_type, digest,
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
        self._spec_id_header_event = TcgEfiSpecIdEvent(spec_id_signature, spec_id_platform_cls,
                                          spec_id_version_minor, spec_id_version_major,
                                          spec_id_errata, spec_id_uint_size, spec_id_num_of_algo,
                                          spec_id_digest_sizes, spec_id_vendor_size,
                                          spec_id_vendor_info)

        return index

    def _parse_event_log_body(self, data:bytes, start_addr:int) -> (TcgImrEventLogEntry, int):
        """
        Parse TCG event log body as single event log entry (TcgImrEventLogEntry) defined at
        https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf

        typedef struct tdTCG_PCR_EVENT2{
            UINT32 pcrIndex;
            UINT32 eventType;
            TPML_DIGEST_VALUES digests;
            UINT32 eventSize;
            BYTE event[eventSize];
        } TCG_PCR_EVENT2;

        """
        index = 0

        blob = BinaryBlob(data, start_addr)

        imr_index, index = blob.get_uint32(index)
        imr_index = imr_index - 1
        event_type, index = blob.get_uint32(index)

        # Fetch digest count and get each digest and its algorithm
        digest_count, index = blob.get_uint32(index)
        digests = []
        for _ in range(digest_count):
            alg_id, index = blob.get_uint16(index)
            alg = next((alg for alg in self._spec_id_header_event.digest_sizes \
                    if alg.algo_id == alg_id), None)
            assert alg is not None, 'No algorithm with such algo_id found'
            digest_size = alg.digest_size
            digest_data, index = blob.get_bytes(index, digest_size)
            digest = TcgDigest(alg_id, digest_data)
            digests.append(digest)
        event_size, index = blob.get_uint32(index)
        event, index = blob.get_bytes(index, event_size)

        # Generate TcgImrEventLogEntry using the info parsed
        entry = TcgImrEventLogEntry(imr_index, event_type, digests, event_size,
                                    event)
        return entry, index
