"""
TCG compliant Event log
"""

import logging
from hashlib import sha1, sha256, sha384, sha512
from cctrusted_base.binaryblob import BinaryBlob
from cctrusted_base.tcg import TcgAlgorithmRegistry
from cctrusted_base.tcg import TcgDigest
from cctrusted_base.tcg import TcgEventType
from cctrusted_base.tcg import TcgEfiSpecIdEvent
from cctrusted_base.tcg import TcgImrEvent
from cctrusted_base.tcg import TcgEfiSpecIdEventAlgorithmSize
from cctrusted_base.tcg import TcgPcClientImrEvent
from cctrusted_base.tcgcel import TcgTpmsCelEvent
from cctrusted_base.tcgcel import TcgCelTypes
from cctrusted_base.tcgcel import TcgTpmsEventPcClientStd
from cctrusted_base.tcgcel import TcgTpmsEventImaTemplate


LOG = logging.getLogger(__name__)

class TcgEventLog:
    """TcgEventLog class.

    This is the common class for tcg event logs to be delivered in different formats.
    Currently TCG supports several event log formats defined in TCG_PCClient Spec,
    Canonical Eventlog Spec, etc.
    This class provides the functionality to convey event logs in different format
    according to request.

    Attributes:
        rec_num: contains the record number of the event log within the imr index
        imr_index: the index of the register that the event log belongs to
        event_type: event type of the event log
        digests: a list of TcgDigest objects
        event_size: size of the event
        event: raw event information
        extra_info: extra information in the event
    """

    TCG_FORMAT_PCCLIENT = 0
    TCG_FORMAT_CEL = 1
    TCG_FORMAT_CEL_TLV = 2
    TCG_FORMAT_CEL_JSON = 3
    TCG_FORMAT_CEL_CBOR = 4

    def __init__(self, rec_num:int, imr_index:int, event_type:TcgEventType, digests:list[TcgDigest],
                 event_size:int, event:bytes, extra_info=None) -> None:
        self._rec_num = rec_num
        self._imr_index = imr_index
        self._event_type = event_type
        self._digests = digests
        self._event_size = event_size
        self._event = event
        self._extra_info = extra_info

    def format_event_log(self, parse_format:str):
        """Format the event log into differen format."""
        if parse_format == self.TCG_FORMAT_PCCLIENT:
            return self._to_tcg_pcclient_format()

        if parse_format == self.TCG_FORMAT_CEL :
            return self._to_tcg_canonical_format()

        return None

    def _to_tcg_pcclient_format(self):
        """The function to convert event log data into event log
           following TCG Pcclient Spec.

           Return different class according to event type
        """
        if (self._event_type == TcgEventType.EV_NO_ACTION and self._rec_num == 0 and
            self._imr_index == 0):
            return TcgPcClientImrEvent(self._imr_index, self._event_type, self._digests[0].hash,
                                       self._event_size, self._event)

        return TcgImrEvent(self._imr_index, self._event_type, self._digests, self._event_size,
                               self._event)

    def _to_tcg_canonical_format(self):
        """The function to convert event log data into event log following
           Canonical Eventlog Spec.
        """

        # Determine content type and construct data according to event type.
        # Now only consider PCClient events and IMA events
        if self._event_type == TcgEventType.IMA_MEASUREMENT_EVENT:
            content_type = TcgCelTypes.CEL_IMA_TEMPLATE
            content_data = TcgTpmsEventImaTemplate(self._event,
                                                   self._extra_info["template_name"])
        else:
            content_type = TcgCelTypes.CEL_PCCLIENT_STD
            content_data = TcgTpmsEventPcClientStd(self._event_type, self._event)

        event = TcgTpmsCelEvent(self._rec_num,
                                self._digests,
                                content_type,
                                self._imr_index,
                                None,
                                content_data)

        # return basic CEL event
        # can switch encoding by calling the TcgTpmsCelEvent.encoding()
        return event

class EventLogs:
    """EventLogs class.

    This class contains the all event logs available on the system.

    Attributes:
        boot_time_data: raw data containing all boot time event logs
        runtime_data: raw data containing runtime event logs(now IMA events)
        event_logs: all parsed event logs
        count: total number of event logs
        parse_format: event log format used for parsing
    """
    spec_id_header_event = None

    def __init__(self, boot_time_data:bytes, runtime_data:bytes, parse_format:str=None) -> None:
        self._boot_time_data = boot_time_data
        self._runtime_data = runtime_data
        self._event_logs = []
        self._count:int = 0
        self._parse_format:str = parse_format
        # Initiate the record number list for each index with default value 0
        self.event_logs_record_number_list = [0] * 24

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
            LOG.info("No event log found.")
            return

        if is_raw:
            LOG.info("RAW UEFI EVENT LOG DATA: ---------------------------------------------------")
            blob = BinaryBlob(self._boot_time_data, 0)
            blob.dump()

            if self._runtime_data is not None:
                # pylint: disable-next=line-too-long
                LOG.info("RAW RUNTIME EVENT LOG DATA: ------------------------------------------------")
                blob = BinaryBlob(self._runtime_data, 0)
                blob.dump()

            LOG.info("End: -----------------------------------------------------------------------")
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
            if start == self._count:
                LOG.info("Input start equal to count. No more event log returned.")
                self._event_logs = []
                return

            if not 0 <= start < self._count:
                # pylint: disable-next=line-too-long
                LOG.error("Invalid input start. Start must be number larger than 0 and smaller than total event log count.")
                raise ValueError("Invalid parameter start.")

            self._event_logs = self._event_logs[start:]

        if count is not None:
            if not 0 < count <= len(self._event_logs):
                # pylint: disable-next=line-too-long
                LOG.error("Invalid input count. count must be number larger than 0 and smaller than total event log count.")
                raise ValueError("Invalid parameter count.")

            self._event_logs = self._event_logs[:count]

    def _get_record_number(self, imr_index:int) -> int:
        """Fetch the record number maintained separately by index.
           Increment the number to be prepared for next measurement.

        Args:
            imr_index: the imr index used to fetch certain record number

        Returns:
            The record number
        """
        rec_num = self.event_logs_record_number_list[imr_index]
        self.event_logs_record_number_list[imr_index] += 1

        return rec_num

    def _parse(self) -> None:
        """Parse event log data into TCG compatible forms.

        Run through all event log data and parse the contents accordingly
        Save the parsed event logs into TcgEventLog.
        """
        if self._boot_time_data is None:
            LOG.error("No boot time event log found.")
            return

        blob = BinaryBlob(self._boot_time_data, 0)
        index = 0

        while index < len(self._boot_time_data):
            start = index
            imr, index = blob.get_uint32(index)
            event_type, index = blob.get_uint32(index)

            if imr == 0xFFFFFFFF:
                break

            if event_type == TcgEventType.EV_NO_ACTION and self._count == 0:
                spec_id_event, event_len = \
                    self._parse_spec_id_event_log(self._boot_time_data[start:])
                index = start + event_len
                self._event_logs.append(spec_id_event.format_event_log(self._parse_format))
                self._count += 1
            else:
                event_log, event_len = self._parse_event_log(self._boot_time_data[start:])
                index = start + event_len
                self._event_logs.append(event_log.format_event_log(self._parse_format))
                self._count += 1

        if self._runtime_data is None:
            return

        for event in self._runtime_data.splitlines():
            event_log = self._parse_ima_event_log(event)
            self._event_logs.append(
                event_log.format_event_log(TcgEventLog.TCG_FORMAT_CEL))
            self._count += 1

    def _parse_spec_id_event_log(self, data:bytes) -> (TcgEventLog, int):
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
            A common TcgEventLog containing the Specification ID version event
            An int specifying the event size
        """
        index = 0

        blob = BinaryBlob(data, 0)

        imr_index, index = blob.get_uint32(index)
        header_imr = imr_index - 1
        header_event_type, index = blob.get_uint32(index)

        rec_num = self._get_record_number(header_imr)

        digest, index = blob.get_bytes(index, 20)  # 20 zero for digest
        # Convert digest to common TcgDigest type
        digest = TcgDigest(TcgAlgorithmRegistry.TPM_ALG_ERROR, digest)
        digests = []
        digests.append(digest)

        header_event_size, index = blob.get_uint32(index) # 4 bytes containing event size
        header_event, _ = blob.get_bytes(index, header_event_size)

        specification_id_header = TcgEventLog(rec_num, header_imr, header_event_type, digests,
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
        EventLogs.spec_id_header_event = \
            TcgEfiSpecIdEvent(spec_id_signature, spec_id_platform_cls,
                              spec_id_version_minor, spec_id_version_major,
                              spec_id_errata, spec_id_uint_size, spec_id_num_of_algo,
                              spec_id_digest_sizes, spec_id_vendor_size,
                              spec_id_vendor_info)

        return specification_id_header, index

    def _parse_event_log(self, data:bytes) -> (TcgEventLog, int):
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
            A TcgEventLog containing the event information
            An int specifying the event size
        """
        index = 0

        blob = BinaryBlob(data, 0)

        imr_index, index = blob.get_uint32(index)
        imr_index = imr_index - 1
        event_type, index = blob.get_uint32(index)

        rec_num = self._get_record_number(imr_index)

        # Fetch digest count and get each digest and its algorithm
        digest_count, index = blob.get_uint32(index)
        digests = []
        for _ in range(digest_count):
            alg_id, index = blob.get_uint16(index)
            alg = next((alg for alg in \
                        EventLogs.spec_id_header_event.digest_sizes \
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
        entry = TcgEventLog(rec_num, imr_index, event_type, digests, event_size,
                                    event)
        return entry, index

    # pylint: disable=c0301
    def _parse_ima_event_log(self, event:bytes) -> TcgEventLog:
        """Parse ascii IMA events gathered during runtime.
        
        Sample event and format:
        IMR index | Template hash | Template name | Event data according to template
        10 1e762ca412a3ef388ddcab416e2eb382d9d1e356 ima-ng sha384:74ccc46104f42db070375e6876a23aeaa3c2ae458888475baaa171c3fb7001b0fc385ed08420d5f60620924fc64d0b80 /etc/lsb-release

        Args:
            event: IMA ascii raw event

        Returns:
            A TcgEventLog object containing the ima event log
        """

        # Split the IMA ascii event log entry using space for processing
        elements = event.decode().strip().split(" ")

        # the first element stores the IMR index
        # the second element stores the digest
        # the third element stores the template name
        # rest contains the raw event data
        imr_idx = 0
        digest_idx = 1
        template_idx = 2

        rec_num = self._get_record_number(int(elements[imr_idx]))

        # Merge the elements left as event data
        event = bytes(" ".join(elements[template_idx+1:]), "utf-8")
        event_size = len(event)

        # Use digest size to figure out the algorithm id
        digests = []
        digest_size = len(elements[digest_idx])/2
        alg_id = TcgAlgorithmRegistry.TPM_ALG_ERROR
        if digest_size in TcgAlgorithmRegistry.TPM_ALG_HASH_DIGEST_SIZE_TABLE.values():
            for key, value in TcgAlgorithmRegistry.TPM_ALG_HASH_DIGEST_SIZE_TABLE.items():
                if value == digest_size:
                    alg_id = key
                    break
        digest = TcgDigest(alg_id, bytearray.fromhex(elements[digest_idx]))
        digests.append(digest)

        # Put template name within extra info
        extra_info = {
            "template_name": elements[template_idx]
        }

        return TcgEventLog(rec_num, int(elements[imr_idx]),
                           TcgEventType.IMA_MEASUREMENT_EVENT, digests,
                           event_size, event, extra_info)

    @staticmethod
    def replay(event_logs:list) -> dict:
        """
        Replay event logs by IMR index.

        Args:
            event_logs(list): a list of parsed event logs to replay

        Returns:
            A dictionary containing the replay result displayed by IMR index and hash algorithm. 
            Layer 1 key of the dict is the IMR index, the value is another dict which using the
            hash algorithm as the key and the replayed measurement as value.
            Sample value:
                { 0: { 12: <measurement_replayed>}}
        """
        measurement_dict = {}
        for event in event_logs:
            # Check event format before replay, skip event if using unknown format
            if not isinstance(event, (TcgImrEvent, TcgPcClientImrEvent, TcgTpmsCelEvent)):
                LOG.error("Event with unknown format. Skip this one...")
                continue

            # TODO: consider CEL-JSON/CEL-CBOR encoding later
            # extract common attributes from different formats, only consider TLV encoding for now
            if isinstance(event, TcgTpmsCelEvent):
                content_type = event.content_type
                # Align the Canonical types with TCG PCClient Event types
                match content_type:
                    case TcgCelTypes.CEL_IMA_TEMPLATE:
                        event_type = TcgEventType.IMA_MEASUREMENT_EVENT
                    case TcgCelTypes.CEL_PCCLIENT_STD:
                        # For PCClient_STD event,
                        # the event type is store within the content attribute
                        # event_type = event.content.value[0].value
                        event_type = event.content.event_type

                # TODO: consider the NV_INDEX case later
                imr_index = event.index

                digests = event.digests
            else:
                event_type = event.event_type
                # Skip EV_NO_ACTION event during replay as
                # it will not result in a digest being extended into a PCR
                if event_type == TcgEventType.EV_NO_ACTION:
                    continue
                imr_index = event.imr_index
                digests = event.digests

            # Skip EV_NO_ACTION event during replay as
            # it will not result in a digest being extended into a PCR
            if event_type == TcgEventType.EV_NO_ACTION:
                continue

            # pylint: disable-next=consider-iterating-dictionary
            if imr_index not in measurement_dict.keys():
                measurement_dict[imr_index] = {}

            for digest in digests:
                alg_id = digest.alg.alg_id
                hash_val = digest.hash

                # Check algorithm type and prepare for replay
                match alg_id:
                    case TcgAlgorithmRegistry.TPM_ALG_SHA1:
                        algo = sha1()
                    case TcgAlgorithmRegistry.TPM_ALG_SHA384:
                        algo = sha384()
                    case TcgAlgorithmRegistry.TPM_ALG_SHA256:
                        algo = sha256()
                    case TcgAlgorithmRegistry.TPM_ALG_SHA512:
                        algo = sha512()
                    case _:
                        LOG.error("Unsupported hash algorithm %d", alg_id)
                        continue

                # Initialize value if alg_id not found in dict
                if alg_id not in measurement_dict[imr_index].keys():
                    measurement_dict[imr_index][alg_id] = bytearray(
                        TcgAlgorithmRegistry.TPM_ALG_HASH_DIGEST_SIZE_TABLE[alg_id])

                # Do replay and update the result into dict
                algo.update(measurement_dict[imr_index][alg_id] + hash_val)
                measurement_dict[imr_index][alg_id] = algo.digest()

        return measurement_dict
