
"""
TCG common definitions
"""
import logging
from cctrusted_base.binaryblob import BinaryBlob

LOG = logging.getLogger(__name__)


class TcgAlgorithmRegistry:
    """From TCG specification
    https://trustedcomputinggroup.org/wp-content/uploads/TCG-_Algorithm_Registry_r1p32_pub.pdf.
    """

    TPM_ALG_ERROR = 0x0
    TPM_ALG_RSA = 0x1
    TPM_ALG_SHA1 = 0x4
    TPM_ALG_SHA256 = 0xB
    TPM_ALG_SHA384 = 0xC
    TPM_ALG_SHA512 = 0xD
    TPM_ALG_ECDSA = 0x18

    TPM_ALG_TABLE = {
        TPM_ALG_RSA: "TPM_ALG_RSA",
        TPM_ALG_SHA1: "TPM_ALG_SHA1",
        TPM_ALG_SHA256: "TPM_ALG_SHA256",
        TPM_ALG_SHA384: "TPM_ALG_SHA384",
        TPM_ALG_SHA512: "TPM_ALG_SHA512",
        TPM_ALG_ECDSA: "TPM_ALG_ECDSA"
    }

    TPM_ALG_HASH_DIGEST_SIZE_TABLE = {
        TPM_ALG_SHA1: 20,
        TPM_ALG_SHA256: 32,
        TPM_ALG_SHA384: 48,
        TPM_ALG_SHA512: 64
    }

    @staticmethod
    def get_algorithm_string(alg_id: int) -> str:
        """Return algorithms name from ID.

        Args:
            alg_id: algorithm ID

        Returns:
            A string containing the corresponding algorithm name
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
        """Algorithms ID."""
        return self._alg_id

    def __str__(self):
        """Name string."""
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
        """Algorithms for the hash of digest."""
        return TcgAlgorithmRegistry(self._alg_id)

    @property
    def hash(self) -> list:
        """Hash of digest."""
        return self._hash

class TcgEventType:
    """TCG EventType defined at
    https://trustedcomputinggroup.org/wp-content/uploads/PC-Client-Platform-Firmware-Profile-Version-1.06-Revision-52_pub.pdf.
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
    EV_POST_CODE2 = 0x13

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
    EV_EFI_PLATFORM_FIRMWARE_BLOB2 = EV_EFI_EVENT_BASE + 0xa
    EV_EFI_HANDOFF_TABLES2 = EV_EFI_EVENT_BASE + 0xb
    EV_EFI_VARIABLE_BOOT2 = EV_EFI_EVENT_BASE + 0xc
    EV_EFI_GPT_EVENT2 = EV_EFI_EVENT_BASE + 0xd
    EV_EFI_HCRTM_EVENT = EV_EFI_EVENT_BASE + 0x10
    EV_EFI_VARIABLE_AUTHORITY = EV_EFI_EVENT_BASE + 0xe0
    EV_EFI_SPDM_FIRMWARE_BLOB = EV_EFI_EVENT_BASE + 0xe1
    EV_EFI_SPDM_FIRMWARE_CONFIG = EV_EFI_EVENT_BASE + 0xe2
    EV_EFI_SPDM_DEVICE_POLICY = EV_EFI_EVENT_BASE + 0xe3
    EV_EFI_SPDM_DEVICE_AUTHORITY = EV_EFI_EVENT_BASE + 0xe4

    # IMA event type defined aligned with MSFT
    IMA_MEASUREMENT_EVENT = 0x14

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
        EV_POST_CODE2: "EV_POST_CODE2",
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
        EV_EFI_VARIABLE_AUTHORITY: "EV_EFI_VARIABLE_AUTHORITY",
        EV_EFI_PLATFORM_FIRMWARE_BLOB2: "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
        EV_EFI_HANDOFF_TABLES2: "EV_EFI_HANDOFF_TABLES2",
        EV_EFI_VARIABLE_BOOT2: "EV_EFI_VARIABLE_BOOT2",
        EV_EFI_GPT_EVENT2: "EV_EFI_GPT_EVENT2",
        EV_EFI_HCRTM_EVENT: "EV_EFI_HCRTM_EVENT",
        EV_EFI_SPDM_FIRMWARE_BLOB: "EV_EFI_SPDM_FIRMWARE_BLOB",
        EV_EFI_SPDM_FIRMWARE_CONFIG: "EV_EFI_SPDM_FIRMWARE_CONFIG",
        EV_EFI_SPDM_DEVICE_POLICY: "EV_EFI_SPDM_DEVICE_POLICY",
        EV_EFI_SPDM_DEVICE_AUTHORITY: "EV_EFI_SPDM_DEVICE_AUTHORITY",
        IMA_MEASUREMENT_EVENT: "IMA_MEASUREMENT_EVENT"
    }

    def __init__(self, event_type:int) -> None:
        if event_type not in TcgEventType.TCG_EVENT_TYPE_TABLE:
            raise ValueError(f'invalid parameter event_type {event_type}')
        self._event_type = event_type

    @staticmethod
    def get_event_type_string(event_type:int) -> str:
        """Get event type string from index.

        Args:
            event_type: event type value

        Returns:
            A string specifying the human readable event type
        """
        if event_type in TcgEventType.TCG_EVENT_TYPE_TABLE:
            return TcgEventType.TCG_EVENT_TYPE_TABLE[event_type]
        return "UNKNOWN"

    @property
    def event_type(self) -> int:
        """Event type."""
        return self._event_type

    def __str__(self) -> str:
        """Event type string."""
        return self.get_event_type_string(self._event_type)

class TcgImrEvent:
    """TCG IMR Event struct defined at
    https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf.

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
        """IMR index of the event."""
        return self._imr_index

    @property
    def event_type(self) -> TcgEventType:
        """Event type of the event."""
        return self._event_type

    @property
    def digests(self) -> list[TcgDigest]:
        """Digests of the event."""
        return self._digests

    @property
    def event_size(self) -> int:
        """Event size of the event."""
        return self._event_size

    @property
    def event(self) -> bytes:
        """Event data."""
        return self._event

    def parse_event_data(self):
        """Parse event data according to event type."""
        match self._event_type:
            case (TcgEventType.EV_EFI_VARIABLE_DRIVER_CONFIG | TcgEventType.EV_EFI_VARIABLE_BOOT |
                  TcgEventType.EV_EFI_VARIABLE_BOOT2 | TcgEventType.EV_EFI_VARIABLE_AUTHORITY):
                # event data compliant to UEFI_VARIABLE_DATA
                return TcgUefiVariableData.parse(self._event)
            case (TcgEventType.EV_POST_CODE2 | TcgEventType.EV_S_CRTM_CONTENTS |
                  TcgEventType.EV_EFI_PLATFORM_FIRMWARE_BLOB2):
                # event data compliant to UEFI_PLATFORM_FIRMWARE_BLOB2
                return TcgUefiPlatformFirmwareBlob2.parse(self._event)
            case TcgEventType.EV_POST_CODE:
                # event data compliant to UEFI_PLATFORM_FIRMWARE_BLOB
                return TcgUefiPlatformFirmwareBlob.parse(self._event)
            case TcgEventType.EV_EFI_HANDOFF_TABLES2:
                # event data compliant to UEFI_HANDOFF_TABLE_POINTERS2
                return TcgUefiHandoffTablePointers2.parse(self._event)
            case (TcgEventType.EV_ACTION | TcgEventType.EV_EFI_ACTION |
                  TcgEventType.EV_PLATFORM_CONFIG_FLAGS | TcgEventType.EV_EFI_HCRTM_EVENT):
                # event data is ascii string
                return self._event.decode("ascii")
            case _:
                # for other types, return raw event data
                return self._event

    def dump(self):
        """Dump data."""
        # pylint: disable-next=line-too-long
        LOG.info("----------------------------------Event Log Entry---------------------------------")
        LOG.info("IMR               : %d", self._imr_index)
        LOG.info("Type              : 0x%X (%s)", self._event_type,
                                 TcgEventType.get_event_type_string(self._event_type))
        count = 0
        for digest in self._digests:
            LOG.info("Algorithm_id[%d]   : %d (%s)", count, digest.alg.alg_id,
                    TcgAlgorithmRegistry.get_algorithm_string(digest.alg.alg_id))
            LOG.info("Digest[%d]:", count)
            digest_blob = BinaryBlob(digest.hash)
            digest_blob.dump()
            count += 1
        LOG.info("Event:")
        event_blob = BinaryBlob(self._event)
        event_blob.dump()

class TcgPcClientImrEvent:
    """TCG TCG_PCClientPCREvent defined at
    https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf.

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
        """IMR index of the event."""
        return self._imr_index

    @property
    def event_type(self):
        """Event type of the event."""
        return self._event_type

    @property
    def digest(self):
        """Digest of the event."""
        return self._digest

    @property
    def event_data_size(self):
        """Event data size of the event."""
        return self._event_data_size

    @property
    def event(self):
        """Event data."""
        return self._event

    def dump(self):
        """Dump data."""
        LOG.info("--------------------Header Specification ID Event--------------------------")
        LOG.info("IMR               : %d", self._imr_index)
        LOG.info("Type              : 0x%X (%s)", self._event_type,
                TcgEventType.get_event_type_string(self._event_type))
        LOG.info("Digest:")
        digest_blob = BinaryBlob(self._digest)
        digest_blob.dump()
        LOG.info("Event:")
        blob = BinaryBlob(self._event)
        blob.dump()

class TcgEfiSpecIdEvent:
    """TCG TCG_EfiSpecIDEventStruct defined at
    https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf.

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
        """Signature of the event."""
        return self._signature

    @property
    def platform_class(self) -> int:
        """Platform class of the event."""
        return self._platform_class

    @property
    def spec_version_minor(self) -> int:
        """Specification minor version of the event."""
        return self._spec_version_minor

    @property
    def sepc_version_major(self) -> int:
        """Specification major version of the event."""
        return self._sepc_version_major

    @property
    def spec_errata(self) -> int:
        """Specification errata of the event."""
        return self._spec_errata

    @property
    def uintn_size(self) -> int:
        """Uintn size of the event."""
        return self._uintn_size

    @property
    def number_of_algos(self) -> int:
        """Number of algorithms of the event."""
        return self._number_of_algos

    @property
    def digest_sizes(self):
        """Digest size of the event."""
        return self._digest_sizes

    @property
    def vendor_info_size(self):
        """Vendor info size of the event."""
        return self._vendor_info_size

    @property
    def vendor_info(self):
        """Vendor info of the event."""
        return self._vendor_info

class TcgEfiSpecIdEventAlgorithmSize:
    """TCG TCG_EfiSpecIdEventAlgorithmSize defined at
    https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf.

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
        """Algorithm Id."""
        return self._algo_id

    @property
    def digest_size(self):
        """Digest_size."""
        return self._digest_size

class TcgUefiVariableData:
    """TCG UEFI_VARIABLE_DATA defined at
    https://trustedcomputinggroup.org/wp-content/uploads/PC-Client-Platform-Firmware-Profile-Version-1.06-Revision-52_pub.pdf.
    """
    def __init__(
        self,
        variable_name:bytes=None,
        unicode_name_length:int=None,
        variable_data_length:int=None,
        unicode_name:bytearray=None,
        variable_data:list[int]=None
    ) -> None:
        self._variable_name = variable_name
        self._unicode_name_length = unicode_name_length
        self._variable_data_length = variable_data_length
        self._unicode_name = unicode_name
        self._variable_data = variable_data

    @property
    def variable_name(self):
        """Variable name."""
        return self._variable_name

    @property
    def unicode_name_length(self):
        """Length of unicode name."""
        return self._unicode_name_length

    @property
    def variable_data_length(self):
        """Length of variable data."""
        return self._variable_data_length

    @property
    def unicode_name(self):
        """Unicode name."""
        return self._unicode_name

    @property
    def variable_data(self):
        """Variable data."""
        return self._variable_data

    @classmethod
    def parse(cls, raw_data:bytes):
        """Parse TcgUefiVariableData from raw event data"""
        blob = BinaryBlob(raw_data, 0)
        index = 0

        variable_name, index = blob.get_bytes(index, 16)
        unicode_name_length, index = blob.get_uint64(index)
        variable_data_length, index = blob.get_uint64(index)
        unicode_name, index = blob.get_bytes(index, unicode_name_length*2)
        variable_data = []
        for _ in range(variable_data_length):
            data, index = blob.get_uint8(index)
            variable_data.append(data)
        return TcgUefiVariableData(variable_name, unicode_name_length,
                                   variable_data_length, unicode_name, variable_data)

class TcgUefiPlatformFirmwareBlob2:
    """TCG UEFI_PLATFORM_FIRMWARE_BLOB2 defined at
    https://trustedcomputinggroup.org/wp-content/uploads/PC-Client-Platform-Firmware-Profile-Version-1.06-Revision-52_pub.pdf.
    """
    def __init__(
        self,
        blob_description_size:int=None,
        blob_description:bytes=None,
        blob_base:int=None,
        blob_length:int=None
    ) -> None:
        self._blob_description_size = blob_description_size
        self._blob_description = blob_description
        self._blob_base = blob_base
        self._blob_length = blob_length

    @property
    def blob_description(self):
        """Blob description."""
        return self._blob_description

    @property
    def blob_description_size(self):
        """Blob description size."""
        return self._blob_description_size

    @property
    def blob_base(self):
        """Blob base."""
        return self._blob_base

    @property
    def blob_length(self):
        """Blob length."""
        return self._blob_length

    @classmethod
    def parse(cls, raw_data:bytes):
        """Parse TcgUefiPlatformFirmwareBlob from raw event data"""
        blob = BinaryBlob(raw_data, 0)
        index = 0

        blob_description_size, index = blob.get_uint8(index)
        blob_description, index = blob.get_bytes(index, blob_description_size)
        blob_base, index = blob.get_uint64(index)
        blob_length, _ = blob.get_uint64(index)

        return TcgUefiPlatformFirmwareBlob2(blob_description_size, blob_description,
                                            blob_base, blob_length)

class TcgUefiPlatformFirmwareBlob:
    """TCG UEFI_PLATFORM_FIRMWARE_BLOB defined at
    https://trustedcomputinggroup.org/wp-content/uploads/PC-Client-Platform-Firmware-Profile-Version-1.06-Revision-52_pub.pdf.
    """
    def __init__(self, blob_base:int=None, blob_length:int=None) -> None:
        self._blob_base = blob_base
        self._blob_length = blob_length

    @property
    def blob_base(self):
        """Blob base"""
        return self._blob_base

    @property
    def blob_length(self):
        """Blob Length"""
        return self._blob_length

    @classmethod
    def parse(cls, raw_data:bytes):
        """Parse TcgUefiPlatformFirmwareBlob from raw event data"""
        blob = BinaryBlob(raw_data, 0)
        index = 0

        blob_base, index = blob.get_uint64(index)
        blob_length, _ = blob.get_uint64(index)

        return TcgUefiPlatformFirmwareBlob(blob_base, blob_length)

class TcgUefiHandoffTablePointers2:
    """TCG UEFI_HANDOFF_TABLE_POINTERS2 defined at
    https://trustedcomputinggroup.org/wp-content/uploads/PC-Client-Platform-Firmware-Profile-Version-1.06-Revision-52_pub.pdf.
    """
    def __init__(
        self,
        table_entry=None,
        table_description_size:int=None,
        table_description:bytearray=None,
        number_of_tables:int=None
        ) -> None:
        self._table_description_size = table_description_size
        self._table_description = table_description
        self._number_of_tables = number_of_tables
        self._table_entry = table_entry

    @property
    def table_description_size(self):
        """Table description size."""
        return self._table_description_size

    @property
    def table_description(self):
        """Table description."""
        return self._table_description

    @property
    def number_of_tables(self):
        """Number of tables."""
        return self._number_of_tables

    @property
    def table_entry(self):
        """Table entries."""
        return self._table_entry

    @classmethod
    def parse(cls, raw_data:bytes):
        """Parse raw data into UEFI_HANDOFF_TABLE_POINTERS2 structure."""
        blob = BinaryBlob(raw_data, 0)
        index = 0

        table_description_size, index = blob.get_uint8(index)
        table_description, index = blob.get_bytes(index, table_description_size)
        num_of_table, index = blob.get_uint64(index)
        table_entries = []
        if num_of_table > 0:
            size = (len(raw_data) - index)/num_of_table
        for _ in range(num_of_table):
            table_data, index = blob.get_bytes(index, size)
            table_entries.append(table_data)
        return TcgUefiHandoffTablePointers2(table_entries, table_description_size,
                                            table_description, num_of_table)
