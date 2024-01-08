"""TDX specific check."""

import pytest
import logging
import re
import tests.test_sdk as test_sdk
from cctrusted_base.ccel import CCEL
from cctrusted_base.tcg import TcgAlgorithmRegistry
from cctrusted_vm.sdk import CCTrustedVmSdk
from cctrusted_vm.cvm import TdxVM

LOG = logging.getLogger(__name__)

class TestCCTrustedVmSdkTdx(test_sdk.TestCCTrustedVmSdk):
    """TDX specific check."""

    MEASUREMENT_COUNT = 4
    """Intel TDX TDREPORT provides the 4 measurement registers by default."""

    PROC_CMDLINE= "/proc/cmdline"

    IMA_SUPPORTED_POLICIES = ["critical_data", "tcb", "fail_securely", ""]
    """IMA supported policies.
        When the policy is not specified or empty ("ima_policy="), the kernel
    will measure boot_aggregate by default.
    """

    def test_get_default_algorithms(self):
        """Test default algorithm is supported."""
        algo = CCTrustedVmSdk.inst().get_default_algorithms()
        assert algo is not None
        assert algo.alg_id == TcgAlgorithmRegistry.TPM_ALG_SHA384

    def test_get_measurement_count(self):
        """Test measurement count is 4 (RTMR count)."""
        count = CCTrustedVmSdk.inst().get_measurement_count()
        assert count == TestCCTrustedVmSdkTdx.MEASUREMENT_COUNT

    def get_ccel(self):
        ccel_data = None
        try:
            with open(TdxVM.ACPI_TABLE_FILE, "rb") as f:
                ccel_data = f.read()
        except (PermissionError, OSError):
            LOG.error("Need root permission to open file %s", TdxVM.ACPI_TABLE_FILE)
        assert len(ccel_data) > 0 and ccel_data[0:4] == b'CCEL', \
            "Invalid CCEL table"
        return CCEL(ccel_data)

    def check_imr(self, imr_index: int, alg_id: int, ccel_data: CCEL):
        """Check individual IMR.
        Args:
            imr_index: an integer specified the IMR index.
            alg_id: an integer specified the hash algorithm.
            ccel_data: CCEL data for comparison.
        """
        assert imr_index >= 0 and imr_index < TestCCTrustedVmSdkTdx.MEASUREMENT_COUNT
        assert ccel_data is not None
        assert alg_id == TcgAlgorithmRegistry.TPM_ALG_SHA384
        imr = CCTrustedVmSdk.inst().get_measurement([imr_index, alg_id])
        assert imr is not None
        digest_obj = imr.digest(alg_id)
        assert digest_obj is not None
        digest_alg_id = digest_obj.alg.alg_id
        assert digest_alg_id == TcgAlgorithmRegistry.TPM_ALG_SHA384
        digest_hash = digest_obj.hash
        assert digest_hash is not None
        # LOG.info(f"{digest_hash.hex()}")
        #TODO: compare the digest hash against the CCEL data.

    def test_get_measurement(self):
        """Test IMA result."""
        cmdline = None
        try:
            with open(TestCCTrustedVmSdkTdx.PROC_CMDLINE) as proc_cmdline:
                cmdline = proc_cmdline.readline()
        except (PermissionError, OSError):
            LOG.error("Need root permission to open file %s", TestCCTrustedVmSdkTdx.PROC_CMDLINE)
        assert cmdline is not None

        ima_policy = None
        if "ima_hash=sha384" in cmdline:
            m = re.search(r".*ima_policy=(\w+).*", cmdline)
            if m is not None:
                ima_policy = m.group(1)
            if (ima_policy is None or
                ima_policy in TestCCTrustedVmSdkTdx.IMA_SUPPORTED_POLICIES):
                alg = CCTrustedVmSdk.inst().get_default_algorithms()
                ccel = self.get_ccel()
                self.check_imr(0, alg.alg_id, ccel)
                self.check_imr(1, alg.alg_id, ccel)
                self.check_imr(2, alg.alg_id, ccel)
                self.check_imr(3, alg.alg_id, ccel)

    def test_get_eventlog(self):
        """Test get_eventlog result."""
        #TODO: verify the eventlog value.

    def test_get_quote(self):
        """Test get_quote result."""
        #TODO: verify the quote value.
