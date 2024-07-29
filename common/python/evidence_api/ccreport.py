"""
CcReport (i.e. quote) data structures.
"""

import logging
from abc import abstractmethod
from evidence_api.binaryblob import BinaryBlob

LOG = logging.getLogger(__name__)

class CcReportData(BinaryBlob):
    """CcReport Data."""

class CcReportSignature(BinaryBlob):
    """CcReport Signature."""

class CcReport(BinaryBlob):
    """CcReport base class."""

    def __init__(
        self,
        data: bytearray,
        cc_type,
        aux_blob: bytearray=None,
        generation:int=None,
        provider:str=None
    ):
        """Initialize instance with raw data.

        Args:
            data: A bytearray storing the raw data(in configfs-tsm, the data contained in outblob).
            cc_type: An int specifying the TEE type
            aux_blob: A bytearray storing aux data when leveraging configfs-tsm.
            generation: An int specifying generation when leveraging configfs-tsm.
            provider: A string specifying provider when leveraging configfs-tsm.
        """
        super().__init__(data)
        self._cc_type = cc_type
        self._cc_aux_blob = aux_blob
        self._cc_report_generation = generation
        self._cc_provider = provider

    @property
    def cc_type(self):
        """Get the CC (Confidential Computing) type."""
        return self._cc_type

    @property
    def cc_aux_blob(self):
        """Get the aux blob of CC report."""
        return self._cc_aux_blob

    @property
    def cc_report_generation(self):
        """Get the report generation."""
        return self._cc_report_generation

    @property
    def cc_provider(self):
        """Get cc provider."""
        return self._cc_provider

    @abstractmethod
    def get_quoted_data(self) -> CcReportData:
        """Get quoted data."""

    @abstractmethod
    def get_sig(self) -> CcReportSignature:
        """Get quote signature."""

    @abstractmethod
    def dump(self, is_raw=True) -> None:
        """Dump CcReport Data.

        Args:
            is_raw:
                True: dump in hex strings.
                False: dump in human readable texts.
        """
        raise NotImplementedError("Should be implemented by inherited class")
