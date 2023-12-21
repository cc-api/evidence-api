
"""
TCG common definitions
"""
import logging
from cctrusted_base.binaryblob import BinaryBlob

LOG = logging.getLogger(__name__)


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
        """Return algorithms name from ID

        Args:
            alg_id: algorithm ID

        Returns:
            A string containing the corresponding algorithm name

        Raises:
            None
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

    def __init__(self, alg_id=TcgAlgorithmRegistry.TPM_ALG_SHA384,
                 digest_hash=None):
        self._hash: list = digest_hash
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

class TcgEventType:
    """
    TCG EventType defined at
    https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf
    """

    EV_PREBOOT_CERT = 0x0
    EV_POST_CODE = 0x1
    EV_UNUSED = 0x2
    EV_NO_ACTION = 0x3
    EV_SEPARATOR = 0x4
    EV_ACTION = 0x5
    EV_EVENT_TAG = 0x6
    EV_S_CRTM_CONTENTS = 0x7
    EV_S_CRTM_VERSION = 0x8
    EV_CPU_MICROCODE = 0x9
    EV_PLATFORM_CONFIG_FLAGS = 0xa
    EV_TABLE_OF_DEVICES = 0xb
    EV_COMPACT_HASH = 0xc
    EV_IPL = 0xd
    EV_IPL_PARTITION_DATA = 0xe
    EV_NONHOST_CODE = 0xf
    EV_NONHOST_CONFIG = 0x10
    EV_NONHOST_INFO = 0x11
    EV_OMIT_BOOT_DEVICE_EVENTS = 0x12

    EV_EFI_EVENT_BASE = 0x80000000
    EV_EFI_VARIABLE_DRIVER_CONFIG = EV_EFI_EVENT_BASE + 0x1
    EV_EFI_VARIABLE_BOOT = EV_EFI_EVENT_BASE + 0x2
    EV_EFI_BOOT_SERVICES_APPLICATION = EV_EFI_EVENT_BASE + 0x3
    EV_EFI_BOOT_SERVICES_DRIVER = EV_EFI_EVENT_BASE + 0x4
    EV_EFI_RUNTIME_SERVICES_DRIVER = EV_EFI_EVENT_BASE + 0x5
    EV_EFI_GPT_EVENT = EV_EFI_EVENT_BASE + 0x6
    EV_EFI_ACTION = EV_EFI_EVENT_BASE + 0x7
    EV_EFI_PLATFORM_FIRMWARE_BLOB = EV_EFI_EVENT_BASE + 0x8
    EV_EFI_HANDOFF_TABLES = EV_EFI_EVENT_BASE + 0x9
    EV_EFI_VARIABLE_AUTHORITY = EV_EFI_EVENT_BASE + 0x10

    TCG_EVENT_TYPE_TABLE = {
        EV_PREBOOT_CERT: "EV_PREBOOT_CERT",
        EV_POST_CODE: "EV_POST_CODE",
        EV_UNUSED: "EV_UNUSED",
        EV_NO_ACTION: "EV_NO_ACTION",
        EV_SEPARATOR: "EV_SEPARATOR",
        EV_ACTION: "EV_ACTION",
        EV_EVENT_TAG: "EV_EVENT_TAG",
        EV_S_CRTM_CONTENTS: "EV_S_CRTM_CONTENTS",
        EV_S_CRTM_VERSION: "EV_S_CRTM_VERSION",
        EV_CPU_MICROCODE: "EV_CPU_MICROCODE",
        EV_PLATFORM_CONFIG_FLAGS: "EV_PLATFORM_CONFIG_FLAGS",
        EV_TABLE_OF_DEVICES: "EV_TABLE_OF_DEVICES",
        EV_COMPACT_HASH: "EV_COMPACT_HASH",
        EV_IPL: "EV_IPL",
        EV_IPL_PARTITION_DATA: "EV_IPL_PARTITION_DATA",
        EV_NONHOST_CODE: "EV_NONHOST_CODE",
        EV_NONHOST_CONFIG: "EV_NONHOST_CONFIG",
        EV_NONHOST_INFO: "EV_NONHOST_INFO",
        EV_OMIT_BOOT_DEVICE_EVENTS: "EV_OMIT_BOOT_DEVICE_EVENTS",
        EV_EFI_EVENT_BASE: "EV_EFI_EVENT_BASE",
        EV_EFI_VARIABLE_DRIVER_CONFIG: "EV_EFI_VARIABLE_DRIVER_CONFIG",
        EV_EFI_VARIABLE_BOOT: "EV_EFI_VARIABLE_BOOT",
        EV_EFI_BOOT_SERVICES_APPLICATION: "EV_EFI_BOOT_SERVICES_APPLICATION",
        EV_EFI_BOOT_SERVICES_DRIVER: "EV_EFI_BOOT_SERVICES_DRIVER",
        EV_EFI_RUNTIME_SERVICES_DRIVER: "EV_EFI_RUNTIME_SERVICES_DRIVER",
        EV_EFI_GPT_EVENT: "EV_EFI_GPT_EVENT",
        EV_EFI_ACTION: "EV_EFI_ACTION",
        EV_EFI_PLATFORM_FIRMWARE_BLOB: "EV_EFI_PLATFORM_FIRMWARE_BLOB",
        EV_EFI_HANDOFF_TABLES: "EV_EFI_HANDOFF_TABLES",
        EV_EFI_VARIABLE_AUTHORITY: "EV_EFI_VARIABLE_AUTHORITY"
    }

    def __init__(self, event_type:int) -> None:
        if event_type in TcgEventType.TCG_EVENT_TYPE_TABLE:
            raise ValueError(f'invalid parameter event_type {event_type}')
        self._event_type = event_type

    @staticmethod
    def get_event_type_string(event_type:int) -> str:
        """Get event type string from index

        Args:
            event_type: event type value

        Returns:
            A string specifying the human readable event type

        Raises:
            None
        """
        if event_type in TcgEventType.TCG_EVENT_TYPE_TABLE:
            return TcgEventType.TCG_EVENT_TYPE_TABLE[event_type]
        return "UNKNOWN"

    @property
    def event_type(self) -> int:
        """
        Return event type
        """
        return self._event_type

    def __str__(self) -> str:
        """
        Event type string
        """
        return self.get_event_type_string(self._event_type)

class TcgImrEventLogEntry:
    """TCG IMR Event struct defined at
    https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf

    Definition:
    typedef struct tdTCG_PCR_EVENT2{
        UINT32 pcrIndex;
        UINT32 eventType;
        TPML_DIGEST_VALUES digests;
        UINT32 eventSize;
        BYTE event[eventSize];
    } TCG_PCR_EVENT2;
 
    """

    def __init__(self, imr_index:int, event_type:TcgEventType, digests:list[TcgDigest],
                 event_size:int, event:bytes) -> None:
        self._imr_index = imr_index
        self._event_type = event_type
        self._digests = digests
        self._event_size = event_size
        self._event = event

    @property
    def imr_index(self) -> int:
        """
        Get IMR index
        """
        return self._imr_index

    @property
    def event_type(self) -> TcgEventType:
        """
        Get event type
        """
        return self._event_type

    @property
    def digests(self) -> list[TcgDigest]:
        """
        Get digests
        """
        return self._digests

    @property
    def event_size(self) -> int:
        """
        Get event size
        """
        return self._event_size

    @property
    def event(self) -> bytes:
        """
        Get event data
        """
        return self._event

    def dump(self):
        """
        dump data
        """
        LOG.info("-------------------------------Event Log Entry-----------------------------")
        LOG.info("IMR               : %d", self._imr_index)
        LOG.info("Type              : 0x%X (%s)", self._event_type,
                                 TcgEventType.get_event_type_string(self._event_type))
        count = 0
        for digest in self._digests:
            LOG.info("Algorithm_id      : %d (%s)",digest.alg.alg_id,
                    TcgAlgorithmRegistry.get_algorithm_string(digest.alg.alg_id))
            LOG.info("Digest[%d]:", count)
            digest_blob = BinaryBlob(digest.hash)
            digest_blob.dump()
            count += 1

class TcgPcClientImrEvent:
    """TCG TCG_PCClientPCREvent defined at
    https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf

    Definition:
    typedef tdTCG_PCClientPCREvent {
        UINT32 pcrIndex;
        UINT32 eventType;
        BYTE digest[20];
        UINT32 eventDataSize;
        BYTE event[eventDataSize]; //This is actually a TCG_EfiSpecIDEventStruct
    } TCG_PCClientPCREvent;
    """
    def __init__(self, imr_index:int, event_type:int, digest:bytes, event_data_size:int,
                 event:bytes) -> None:
        self._imr_index = imr_index
        self._event_type = event_type
        self._digest = digest
        self._event_data_size = event_data_size
        self._event = event

    @property
    def imr_index(self):
        """
        Return IMR index
        """
        return self._imr_index

    @property
    def event_type(self):
        """
        Return event type
        """
        return self._event_type

    @property
    def digest(self):
        """
        Return digest
        """
        return self._digest

    @property
    def event_data_size(self):
        """
        Return event data size
        """
        return self._event_data_size

    @property
    def event(self):
        """
        Return event
        """
        return self._event

    def dump(self):
        """
        Dump data
        """
        LOG.info("--------------------Header Specification ID Event--------------------------")
        LOG.info("IMR               : %d", self._imr_index)
        LOG.info("Type              : 0x%X (%s)", self._event_type,
                TcgEventType.get_event_type_string(self._event_type))
        LOG.info("Event:")
        blob = BinaryBlob(self._event)
        blob.dump()

class TcgEfiSpecIdEvent:
    """TCG TCG_EfiSpecIDEventStruct defined at
    https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf

    Definition:
    typedef struct tdTCG_EfiSpecIdEventStruct {
        BYTE[16] signature;
        UINT32 platformClass;
        UINT8 specVersionMinor;
        UINT8 specVersionMajor;
        UINT8 specErrata;
        UINT8 uintnSize;
        UINT32 numberOfAlgorithms;
        TCG_EfiSpecIdEventAlgorithmSize[numberOfAlgorithms] digestSizes;
        UINT8 vendorInfoSize;
        BYTE[VendorInfoSize] vendorInfo;
    } TCG_EfiSpecIDEventStruct;
    """

    def __init__(self, sig:bytes, platform_class:int, spec_version_minor:int,
                 spec_version_major:int, spec_errata:int, uintn_size:int,
                 number_of_algos:int, digest_sizes, vendor_info_size:int,
                 vendor_info:bytes) -> None:
        self._signature:bytes = sig
        self._platform_class:int = platform_class
        self._spec_version_minor:int = spec_version_minor
        self._sepc_version_major:int = spec_version_major
        self._spec_errata:int = spec_errata
        self._uintn_size:int = uintn_size
        self._number_of_algos:int = number_of_algos
        self._digest_sizes:list[TcgEfiSpecIdEventAlgorithmSize] = digest_sizes
        self._vendor_info_size:int = vendor_info_size
        self._vendor_info:bytes = vendor_info

    @property
    def signature(self) -> bytes:
        """
        Get signature
        """
        return self._signature

    @property
    def platform_class(self) -> int:
        """
        Get platform class
        """
        return self._platform_class

    @property
    def spec_version_minor(self) -> int:
        """
        Get spec minor version
        """
        return self._spec_version_minor

    @property
    def sepc_version_major(self) -> int:
        """
        Get spec major version
        """
        return self._sepc_version_major

    @property
    def spec_errata(self) -> int:
        """
        Get spec errata
        """
        return self._spec_errata

    @property
    def uintn_size(self) -> int:
        """
        Get uintn size
        """
        return self._uintn_size

    @property
    def number_of_algos(self) -> int:
        """
        Get number of algorithms
        """
        return self._number_of_algos

    @property
    def digest_sizes(self):
        """
        Get digest size
        """
        return self._digest_sizes

class TcgEfiSpecIdEventAlgorithmSize:
    """TCG TCG_EfiSpecIdEventAlgorithmSize defined at
    https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf

    Definiton:
    typedef struct tdTCG_EfiSpecIdEventAlgorithmSize {
        UINT16 algorithmId;
        UINT16 digestSize;
    } TCG_EfiSpecIdEventAlgorithmSize;
    """

    def __init__(self, alg_id:int, digest_size:int) -> None:
        self._algo_id = alg_id
        self._digest_size = digest_size

    @property
    def algo_id(self):
        """
        Get algorithm Id
        """
        return self._algo_id

    @property
    def digest_size(self):
        """
        Get digest_size
        """
        return self._digest_size
