"""
TCG Canonical Event Log common definitions
"""
import logging
from abc import abstractmethod
from cctrusted_base.tcg import TcgDigest
from cctrusted_base.tcg import TcgAlgorithmRegistry
from cctrusted_base.tcg import TcgEventType
from cctrusted_base.eventlog import TcgImrEvent
from cctrusted_base.binaryblob import BinaryBlob

LOG = logging.getLogger(__name__)

class TcgTpmsCelEvent:
    """TCG TPMS_CEL_EVENT defined at
    https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_CEL_v1_r0p30_13feb2021.pdf

    This specification defines the Canonical Event Log Record using TPMS_EVENT data type.
    """

    def __init__(
        self,
        rec_num:int,
        digests:list[TcgDigest],
        content_type:int=None,
        imr:int=None,
        nv_index:int=None,
        content=None,
    ) -> None:
        # Shall not specify both IMR index and NV index
        if imr is not None and nv_index is not None:
            # pylint: disable-next=line-too-long
            LOG.error("Instantiate TPMS_CEL_EVENT with both IMR index and NV index. Failed to instantiate...")
            return

        # Get value either from IMR index or NV index
        if imr is not None:
            self._imr = imr
        else:
            self._nv_index = nv_index

        self._rec_num = rec_num
        self._digests = digests
        self._content_type = content_type

        if not TcgTpmiCelContentType.is_valid_content(content.get_type()):
            LOG.error("Invalid content specified. Failed to instantiate...")
            return
        self._content = content
        # Reserve encoding attribute
        self._encoding = None

    @property
    def rec_num(self):
        """Record number."""
        return self._rec_num

    def set_rec_num(self, rec_num):
        """Set formatted value for rec_num."""
        self._rec_num = rec_num

    @property
    def index(self):
        """IMR index or NV index of the event if specified."""
        if self._imr is not None:
            return self._imr
        return self._nv_index

    def set_imr(self, imr):
        """Set formatted value for IMR index."""
        self._imr = imr

    def set_nv_index(self, nv_index):
        """Set formatted value for NV index."""
        self._nv_index = nv_index

    @property
    def digests(self):
        """Digests of the event."""
        return self._digests

    def set_digests(self, digests):
        """Set formatted value for digests."""
        self._digests = digests

    @property
    def content(self):
        """Content of the event."""
        return self._content

    def set_content(self, content):
        """Set formatted value for content."""
        self._content = content

    @property
    def content_type(self):
        """Content type of event."""
        return self._content_type

    def encoding(self):
        """Get the encoding format of the event"""
        return self._encoding

    def to_pcclient_format(self):
        """Convert CEL event log to PCClient format"""
        if self._content_type == TcgCelTypes.CEL_IMA_TEMPLATE:
            event = self.content.template_data
            return TcgImrEvent(self._imr, TcgEventType.IMA_MEASUREMENT_EVENT,
                               self._digests, len(event), event)
        if self._content_type == TcgCelTypes.CEL_PCCLIENT_STD:
            return TcgImrEvent(self._imr, self.content.event_type, self._digests,
                               len(self.content.event_data), self.content.event_data)
        LOG.error("Unsupported content to parse into TCG PCClient format.")
        return None

    @staticmethod
    def encode(obj, encoding:int=2):
        """Encode the CEL record in certain format"""
        match encoding:
            # TcgEventLog.TCG_FORMAT_CEL_TLV = 2
            case 2:
                # pylint: disable-next=w0212
                obj._encoding = "TLV"
                return TcgTpmsCelEvent._encoded_in_tlv(obj)
            # TcgEventLog.TCG_FORMAT_CEL_JSON = 3
            case 3:
                # pylint: disable-next=w0212
                obj._encoding = "JSON"
                return TcgTpmsCelEvent._encoded_in_json(obj)
            # TcgEventLog.TCG_FORMAT_CEL_JSON = 4
            case 4:
                # pylint: disable-next=w0212
                obj._encoding = "CBOR"
                return TcgTpmsCelEvent._encoded_in_cbor(obj)
            case _:
                LOG.error("Invalid encoding specified. Returning the default encoding TLV")
                # pylint: disable-next=w0212
                obj._encoding = "TLV"
                return TcgTpmsCelEvent._encoded_in_tlv(obj)

    def dump(self):
        """Dump data."""
        encoding = self.encoding()
        match encoding:
            case "TLV":
                rec_num = self.rec_num.value
                imr_index = self.index.value
            case _:
                LOG.error("Unsupported data format for dumping.")
                return

        # pylint: disable-next=line-too-long
        LOG.info("-----------------------------Canonical Event Log Entry----------------------------")
        LOG.info("Encoding          : %s", encoding)
        LOG.info("Rec Num           : %d", rec_num)
        LOG.info("IMR               : %d", imr_index)
        LOG.info("Type              : 0x%X (%s)", self._content_type,
                                 TcgTpmiCelContentType.get_content_type_string(self._content_type))
        LOG.info("Digests:")
        count = 0
        for digest in self._digests.value:
            LOG.info("Algorithm_id[%d]   : %d (%s)", count, digest.type,
                    TcgAlgorithmRegistry.get_algorithm_string(digest.type))
            LOG.info("Digest[%d]:", count)
            digest_blob = BinaryBlob(digest.value)
            digest_blob.dump()
            count += 1
        LOG.info("Contents:")
        count = 0
        for cnt in self._content.value:
            LOG.info("%d: %s = %s", count, cnt.attr_table[cnt.type], cnt.value)
            count += 1

    @staticmethod
    def _encoded_in_tlv(obj):
        """CEL Record encoded in TLV"""
        rec_num = TcgCelRecnum()
        rec_num.set_type(TcgCelTypes.CEL_SEQNUM)
        rec_num.set_value(obj.rec_num)
        obj.set_rec_num(rec_num)

        digests = TcgCelDigests()
        digests.set_type(TcgCelTypes.CEL_DIGESTS)
        d_list = []
        for digest in obj.digests:
            d = TcgTlv()
            d.set_type(digest.alg.alg_id)
            d.set_value(digest.hash)
            d_list.append(d)
        digests.set_value(d_list)
        obj.set_digests(digests)

        content = TcgCelContent()
        # pylint: disable-next=W0212
        content.set_type(obj._content_type)
        content.set_value(obj.content.to_tlv())
        obj.set_content(content)

        index = TcgCelImrNvindex()
        # pylint: disable-next=W0212
        if obj._imr is not None:
            index.set_type(TcgCelTypes.CEL_PCR)
            # pylint: disable-next=W0212
            index.set_value(obj._imr)
            obj.set_imr(index)
        else:
            index.set_type(TcgCelTypes.CEL_NV_INDEX)
            # pylint: disable-next=W0212
            index.set_value(obj._nv_index)
            obj.set_nv_index(index)

        return obj

    @staticmethod
    def _encoded_in_cbor(obj):
        """CEL record encoded in CBOR."""
        raise NotImplementedError

    @staticmethod
    def _encoded_in_json(obj):
        """CEL record encoded in JSON."""
        raise NotImplementedError

class TcgCelTypes:
    """TCG CEL Types."""

    # TCG CEL top level event types
    CEL_SEQNUM = 0x00000000
    CEL_PCR = 0x00000001
    CEL_NV_INDEX = 0x00000002
    CEL_DIGESTS = 0x00000003
    CEL_MGT = 0x00000004
    CEL_PCCLIENT_STD =0x00000005
    CEL_IMA_TEMPLATE = 0x00000007
    CEL_IMA_TLV = 0x00000008

    # CEL_MGT types
    CEL_MGT_TYPE = 0
    CEL_MGT_DATA = 1
    CEL_MGT_CEL_VERSION = 1
    CEL_MGT_CEL_VERSION_MAJOR = 0
    CEL_MGT_CEL_VERSION_MINOR = 1
    CEL_MGT_FIRMWARE_END =2
    CEL_MGT_CEL_TIMESTAMP = 80
    CEL_MGT_STATE_TRANS = 81
    CEL_MGT_STATE_TRANS_SUSPEND = 0
    CEL_MGT_STATE_TRANS_HIBERNATE = 1
    CEL_MGT_STATE_TRANS_KEXEC = 2

    # IMA-TLV specific content types
    IMA_TLV_PATH = 0
    IMA_TLV_DATAHASH = 1
    IMA_TLV_DATASIG = 2
    IMA_TLV_OWNER = 3
    IMA_TLV_GROUP = 4
    IMA_TLV_MODE = 5
    IMA_TLV_TIMESTAMP = 6
    IMA_TLV_LABEL = 7

    # IMA_TEMPLATE specific content types
    IMA_TEMPLATE_NAME = 0
    IMA_TEMPLATE_DATA = 1

    # PCCLIENT_STD content types
    PCCLIENT_STD_TYPE = 0
    PCCLIENT_STD_CONTENT = 1

class TcgTpmiCelContentType:
    """ The TPMI_CEL_CONTENT_TYPE for Canonical Event Log Record defined at
    https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_CEL_v1_r0p30_13feb2021.pdf
    """

    CEL = 0x4
    PCCLIENT_STD = 0x5
    IMA_TEMPLATE = 0x7
    IMA_TLV = 0x8

    CEL_CONTENT_TABLE = {
        CEL: "CEL",
        PCCLIENT_STD: "PCCLIENT_STD",
        IMA_TEMPLATE: "IMA_TEMPLATE",
        IMA_TLV: "IMA_TLV"
    }

    def __init__(self, content_type:int) -> None:
        if content_type not in self.CEL_CONTENT_TABLE:
            raise ValueError("Invalid CEL content type declared.")
        self._content_type = content_type

    @staticmethod
    def is_valid_content(content_type:int) -> bool:
        """Check if the content is valid content."""
        if content_type not in TcgTpmiCelContentType.CEL_CONTENT_TABLE:
            return False
        return True

    @staticmethod
    def get_content_type_string(content_type:int) -> str:
        """Get content type string from index.

        Args:
            content_type: content type value

        Returns:
            A string specifying the human readable content type
        """
        if content_type in TcgTpmiCelContentType.CEL_CONTENT_TABLE:
            return TcgTpmiCelContentType.CEL_CONTENT_TABLE[content_type]
        return "UNKNOWN"

class TcgTpmuEventContent:
    """CEL supported content fields."""
    def __init__(self, event_content) -> None:
        if not isinstance(event_content,
                          (TcgTpmsEventPcClientStd, TcgTpmsEventCelMgt,
                           TcgTpmsEventImaTemplate, TcgImaTlv)):
            LOG.error("Invalid event content used.")
            return
        self._type = type(event_content)
        self._event = event_content

    @property
    def content_type(self):
        """Content type."""
        return self._type

    @property
    def event(self):
        """Event."""
        return self._event

class TcgTlv:
    """Base class for TCG TLV format."""
    def __init__(self, tlv_type:int=None, value=None) -> None:
        self._tlv_type = tlv_type
        self._value = value
        self._attr_table:dict = None

    @abstractmethod
    def set_type(self, tlv_type):
        """Set type for the TLV"""
        self._tlv_type = tlv_type

    @abstractmethod
    def set_value(self, value):
        """Set value for the TLV."""
        self._value = value

    @abstractmethod
    def set_attr_table(self, value):
        """Set the dict of attributes name of the class."""
        self._attr_table = value

    @property
    def type(self):
        """Type of event data"""
        return self._tlv_type

    @property
    def value(self):
        """Value stored in event"""
        return self._value

    @property
    def attr_table(self):
        """Table contains attributes name(string) within the class."""
        return self._attr_table

class TcgCelRecnum(TcgTlv):
    """CEL record number field encoded in TLV."""

    def set_type(self, tlv_type:int=0) -> None:
        """Type for Record number"""
        if tlv_type != 0:
            LOG.error("Type for record number shall be 0")
        self._tlv_type = 0

    def set_value(self, value:int=0x00000000) -> None:
        """Set the sequential number as value."""
        self._value = value

    def set_attr_table(self, value):
        """Set the dict of attributes name of the class."""
        raise NotImplementedError

class TcgCelImrNvindex(TcgTlv):
    """CEL IMR or NV index field encoded in TLV."""

    def set_type(self, tlv_type:int=None) -> None:
        """Set type for CEL_IMR_Nvindex."""
        if tlv_type not in [TcgCelTypes.CEL_PCR, TcgCelTypes.CEL_NV_INDEX]:
            LOG.error("Invalid type declared for TcgCelImrNvindex.")
            return
        self._tlv_type = tlv_type

    def set_value(self, value:int) -> None:
        """Set value for CEL_IMR_Nvindex."""
        self._value = value

    def set_attr_table(self, value):
        """Set the dict of attributes name of the class."""
        raise NotImplementedError

class TcgCelDigests(TcgTlv):
    """CEL_DIGESTS encoded in TLV."""

    def set_type(self, tlv_type:int=None) -> None:
        """Set type for CEL_Digests."""
        if tlv_type != TcgCelTypes.CEL_DIGESTS:
            LOG.error("Invalid type declared for TcgCelDigests.")
            return
        self._tlv_type = tlv_type

    def set_value(self, value=None) -> None:
        """Set value for CEL_DIGESTS."""
        self._value = value

    def set_attr_table(self, value):
        """Set the dict of attributes name of the class."""
        raise NotImplementedError

class TcgCelContent(TcgTlv):
    """CEL_CONTENT encoded in TLV"""

    def set_type(self, tlv_type:int=None) -> None:
        """Set type for CEL_CONTENT."""
        # pylint: disable-next=c0201
        if tlv_type not in TcgTpmiCelContentType.CEL_CONTENT_TABLE.keys():
            LOG.error("Invalid content type %d specified.", tlv_type)
            return
        self._tlv_type = tlv_type

    def set_value(self, value=None) -> None:
        """Set value for CEL_CONTENT."""
        self._value = value

    def set_attr_table(self, value):
        """Set the dict of attributes name of the class."""
        raise NotImplementedError

class TcgTpmuCelMgt:
    """CEL Management Event content."""

    TPMS_CEL_VERSION = [TcgCelTypes.CEL_MGT_CEL_VERSION_MAJOR,
                        TcgCelTypes.CEL_MGT_CEL_VERSION_MINOR]
    TPMI_STATE_TRANS = [TcgCelTypes.CEL_MGT_STATE_TRANS_SUSPEND,
                        TcgCelTypes.CEL_MGT_STATE_TRANS_HIBERNATE,
                        TcgCelTypes.CEL_MGT_STATE_TRANS_KEXEC]

    def __init__(
        self,
        cel_version:int=None,
        cel_timestamp:int=None,
        state_trans:int=None,
        firmware_end=None
    ) -> None:
        if cel_version not in self.TPMS_CEL_VERSION:
            LOG.error("Invalid value specified for cel_version.")
            return
        self._cel_version = cel_version
        self._firmware_end = firmware_end
        self._cel_timestamp = cel_timestamp
        if state_trans not in self.TPMI_STATE_TRANS:
            LOG.error("Invalid value specified for state_trans.")
            return
        self._stat_trans = state_trans

    @property
    def cel_version(self):
        """CEL version."""
        return self._cel_version

    @property
    def cel_timestamp(self):
        """CEL timestamp."""
        return self._cel_timestamp

    @property
    def firmware_end(self):
        """Firemware end."""
        return self._firmware_end

    @property
    def state_trans(self):
        """State trans."""
        return self._stat_trans

    def to_tlv(self):
        """Encode to TLV"""
        raise NotImplementedError

class TcgTpmsEventCelMgt:
    """Structure defines the content of a CEL Management Event"""

    TPMI_CELMGTTYPE_VALUE = {
        "cel_version": TcgCelTypes.CEL_MGT_CEL_VERSION,
        "firmware_end": TcgCelTypes.CEL_MGT_FIRMWARE_END,
        "cel_timestamp": TcgCelTypes.CEL_MGT_CEL_TIMESTAMP,
        "State_trans": TcgCelTypes.CEL_MGT_STATE_TRANS
    }

    def __init__(self, mgt_type:int=None, mgt_data:TcgTpmuCelMgt=None) -> None:
        if mgt_type not in self.TPMI_CELMGTTYPE_VALUE.values():
            LOG.error("Invalid value for TPMI_CELMGTTYPE.")
            return
        self._type = mgt_type
        self._data = mgt_data

    def get_type(self):
        """Return type."""
        return TcgTpmiCelContentType.CEL

    def to_tlv(self):
        """Encode to TLV"""
        LOG.error("Not implemented for TLV encoding.")

class TcgTpmsEventPcClientStd:
    """Content of PCClient_STD Event."""
    # Attributes within TcgTpmsEventPcClientStd
    PCCLIENT_STD_TABLE = {
        TcgCelTypes.PCCLIENT_STD_TYPE: "PCCLIENT_STD_TYPE",
        TcgCelTypes.PCCLIENT_STD_CONTENT: "PCCLIENT_STD_CONTENT"
    }

    def __init__(self, event_type:int=None, event_data:bytearray=None) -> None:
        self._event_type = event_type
        self._event_data = event_data

    @property
    def event_type(self):
        """Event type of PCClient_STD events."""
        return self._event_type

    @property
    def event_data(self):
        """Event data of PCClient_STD events."""
        return self._event_data

    def get_type(self):
        """Return type."""
        return TcgTpmiCelContentType.PCCLIENT_STD

    def to_tlv(self):
        """Encode to TLV."""
        content_list = []
        event_type = TcgTlv(tlv_type=TcgCelTypes.PCCLIENT_STD_TYPE,
                            value=self._event_type)
        event_data = TcgTlv(tlv_type=TcgCelTypes.PCCLIENT_STD_CONTENT,
                            value=self._event_data)
        event_type.set_attr_table(self.PCCLIENT_STD_TABLE)
        event_data.set_attr_table(self.PCCLIENT_STD_TABLE)
        content_list.append(event_type)
        content_list.append(event_data)
        return content_list

class TcgTpmsEventImaTemplate:
    """Content of IMA_TEMPLATE Event."""

    def __init__(self, template_data:str=None, template_name:str=None) -> None:
        self._template_data = template_data
        self._template_name = template_name

    # Attributes within TcgTpmsEventImaTemplate
    IMA_TEMPLATE_TABLE = {
        TcgCelTypes.IMA_TEMPLATE_NAME: "IMA_TEMPLATE_NAME",
        TcgCelTypes.IMA_TEMPLATE_DATA: "IMA_TEMPLATE_DATA"
    }

    @property
    def template_data(self):
        """Template data."""
        return self._template_data

    @property
    def template_name(self):
        """Template name."""
        return self._template_name

    def get_type(self):
        """Return type."""
        return TcgTpmiCelContentType.IMA_TEMPLATE

    def to_tlv(self):
        """Encode to TLV."""
        content_list = []
        template_name = TcgTlv(tlv_type=TcgCelTypes.IMA_TEMPLATE_NAME,
                                value=self._template_name)
        template_data = TcgTlv(tlv_type=TcgCelTypes.IMA_TEMPLATE_DATA,
                                value=self._template_data)
        template_name.set_attr_table(self.IMA_TEMPLATE_TABLE)
        template_data.set_attr_table(self.IMA_TEMPLATE_TABLE)
        content_list.append(template_name)
        content_list.append(template_data)
        return content_list

class TcgImaTlv:
    """Content of IMA-TLV Event. Not implemented now."""
    def __init__(self) -> None:
        pass

    def get_type(self):
        """Return type."""
        return TcgTpmiCelContentType.IMA_TLV

    def to_tlv(self):
        """Encode to TLV"""
        LOG.error("Not implemented for TLV encoding.")
