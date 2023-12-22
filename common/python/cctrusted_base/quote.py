"""
Quote data structures.
"""

import logging
from abc import abstractmethod
from cctrusted_base.binaryblob import BinaryBlob

LOG = logging.getLogger(__name__)

class QuoteData(BinaryBlob):
    """Quote Data."""

class QuoteSignature(BinaryBlob):
    """Quote Signature."""

class Quote(BinaryBlob):
    """Quote base class."""

    @abstractmethod
    def get_quoted_data(self) -> QuoteData:
        """Get quoted data."""

    @abstractmethod
    def get_sig(self) -> QuoteSignature:
        """Get quote signature."""

    @abstractmethod
    def dump(self, is_raw=True) -> None:
        """Dump Quote Data.

        Args:
            is_raw:
                True: dump in hex strings.
                False: dump in human readable texts.
        """
        raise NotImplementedError("Should be implemented by inherited class")
