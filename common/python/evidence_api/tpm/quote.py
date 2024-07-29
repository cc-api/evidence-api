"""
TPM Quote related classes.
"""

import logging
from evidence_api.ccreport import CcReport, CcReportData, CcReportSignature
from evidence_api.binaryblob import BinaryBlob

LOG = logging.getLogger(__name__)

class Tpm2Quote(CcReport):
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

    def __init__(self, data: bytearray, cc_type):
        """Initialize instance with raw data.

        Args:
            data: A bytearray storing the raw data.
        """
        super().__init__(data, cc_type)
        self._quoted_data = None
        self._signature = None

    def set_quoted_data(self, data):
        """Set TPM2 quote header"""
        self._quoted_data = data

    def set_sig(self, sig):
        """Set TPM2 quote signature"""
        self._signature = sig

    def get_quoted_data(self) -> CcReportData:
        """Get TPM2 quote header."""
        # TODO: parse the raw data to get quoted data
        return self._quoted_data.marshal()

    def get_sig(self) -> CcReportSignature:
        """Get TPM2 quote signature."""
        # TODO: parse the raw data to get signature
        return self._signature.marshal()

    def dump(self, is_raw=True) -> None:
        """Dump Quote Data.

        Args:
            is_raw:
                True: dump in hex strings.
                False: dump in human readable texts.
        """
        # TODO: add human readable dump
        LOG.info("======================================")
        LOG.info("TPM2 Quote")
        LOG.info("======================================")
        if is_raw:
            BinaryBlob(self._quoted_data.marshal()).dump()
            BinaryBlob(self._signature.marshal()).dump()
        else:
            LOG.error("Structured TPM2 Quote dump is not available now.")
