"""
CcReport (i.e. quote) data structures.
"""

import logging
from abc import abstractmethod
from cctrusted_base.binaryblob import BinaryBlob

LOG = logging.getLogger(__name__)

class CcReportData(BinaryBlob):
    """CcReport Data."""

class CcReportSignature(BinaryBlob):
    """CcReport Signature."""

class CcReport(BinaryBlob):
    """CcReport base class."""

    def __init__(self, data: bytearray, cc_type):
        """Initialize instance with raw data.

        Args:
            data: A bytearray storing the raw data.
        """
        super().__init__(data)
        self._cc_type = cc_type

    @property
    def cc_type(self):
        """Get the CC (Confidential Computing) type."""
        return self._cc_type

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
