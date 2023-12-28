"""
TPM Quote related classes.
"""

from cctrusted_base.quote import Quote, QuoteData, QuoteSignature

class Tpm2Quote(Quote):
    """TPM 2 Quote.

    References:
    https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part3_Commands_pub.pdf
    Table 91 — TPM2_Quote Response
        Type            Name            Description
        TPM_ST          tag             see clause 6
        UINT32          responseSize
        TPM_RC          responseCode
        TPM2B_ATTEST    quoted          the quoted information
        TPMT_SIGNATURE  signature       the signature over quoted
    In our code, we will store the related info:
        data: quoted
        sig: signature
    """

    def __init__(self, data: bytearray):
        """Initialize instance with raw data.

        Args:
            data: A bytearray storing the raw data.
        """
        super().__init__(data)
        # TODO: parse raw data into header, body and sigature

    def get_quoted_data(self) -> QuoteData:
        """Get TPM2 quote header."""
        # TODO: parse the raw data to get quoted data
        return None

    def get_sig(self) -> QuoteSignature:
        """Get TPM2 quote signature."""
        # TODO: parse the raw data to get signature
        return None

    def dump(self, is_raw=True) -> None:
        """Dump Quote Data.

        Args:
            is_raw:
                True: dump in hex strings.
                False: dump in human readable texts.
        """
        # TODO: add human readable dump
        super().dump()
