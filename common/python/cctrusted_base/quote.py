"""
Quote data structures
"""

from abc import ABC, abstractmethod



class QuoteHeader(ABC):
    """
    Quote Header abstract class (interface)
    """

    @abstractmethod
    def get_data(self) -> bytearray:
        """
        Get raw data
        """
        raise NotImplementedError("Should be implemented by inherited class")

class QuoteBody(ABC):
    """
    Quote Body abstract class (interface)
    """

    @abstractmethod
    def get_data(self) -> bytearray:
        """
        Get raw data
        """
        raise NotImplementedError("Should be implemented by inherited class")

QuoteSignature = bytearray

class Quote(ABC):
    """
    Quote abstract class (interface)
    """

    @abstractmethod
    def get_header(self) -> QuoteHeader:
        """
        Get quote header.
        """
        raise NotImplementedError("Should be implemented by inherited class")

    @abstractmethod
    def get_body(self) -> QuoteBody:
        """
        Get quote body.
        The body (excludes the header) correspongs to the data to be signed.
        """
        raise NotImplementedError("Should be implemented by inherited class")

    @abstractmethod
    def get_sig(self) -> QuoteSignature:
        """
        Get quote signature.
        """
        raise NotImplementedError("Should be implemented by inherited class")

class Tpm2Quote(Quote):
    """
    TPM Quote
    https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part3_Commands_pub.pdf
    Table 91 — TPM2_Quote Response
        Type            Name            Description
        TPM_ST          tag             see clause 6
        UINT32          responseSize
        TPM_RC          responseCode
        TPM2B_ATTEST    quoted          the quoted information
        TPMT_SIGNATURE  signature       the signature over quoted
    In our code, these info will be grouped into 3 properties according to the definition of Quote
        header: includes tag, responseSize and responseCode
        body: quoted
        sig: signature
    """

    def __init__(self, data: bytearray):
        self._data = data
        # TODO: parse raw data into header, body and sigature

    def get_header(self) -> QuoteHeader:
        """
        Get TPM2 quote header which includes tag, responseSize and responseCode
        """
        # TODO: parse the raw data to get header
        return None

    def get_body(self) -> QuoteBody:
        """
        Get TPM2 quote body
        """
        # TODO: parse the raw data to get body
        return None

    def get_sig(self) -> QuoteSignature:
        """
        Get TPM2 quote signature
        """
        # TODO: parse the raw data to get signature
        return None
