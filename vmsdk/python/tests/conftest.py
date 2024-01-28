"""Local conftest.py containing directory-specific hook implementations."""

import pytest
from cctrusted_base.tcg import TcgAlgorithmRegistry
from cctrusted_base.tdx.rtmr import TdxRTMR
from cctrusted_vm.cvm import ConfidentialVM
from cctrusted_vm.sdk import CCTrustedVmSdk
import tdx_check

cnf_default_alg = {
    ConfidentialVM.TYPE_CC_TDX: TcgAlgorithmRegistry.TPM_ALG_SHA384
}
"""Configurations of default algorithm.
The configurations could be different for different confidential VMs.
e.g. TDX use sha384 as the default.
"""

cnf_measurement_cnt = {
    ConfidentialVM.TYPE_CC_TDX: TdxRTMR.RTMR_COUNT
}
"""Configurations of measurement count.
The configurations could be different for different confidential VMs.
"""

cnf_measurement_check = {
    ConfidentialVM.TYPE_CC_TDX: tdx_check.tdx_check_measurement_imrs
}
"""Configurations of measurement check functions.
The configurations could be different for different confidential VMs.
"""

cnf_quote_check_valid_input = {
    ConfidentialVM.TYPE_CC_TDX: tdx_check.tdx_check_quote_with_valid_input
}
"""Configurations of quote check functions for valid input.
The configurations could be different for different confidential VMs.
"""

cnf_quote_check_invalid_input = {
    ConfidentialVM.TYPE_CC_TDX: tdx_check.tdx_check_quote_with_invalid_input
}
"""Configurations of quote check functions for invalid input.
The configurations could be different for different confidential VMs.
"""

@pytest.fixture(scope="module")
def vm_sdk():
    """Get VMSDK instance."""
    return CCTrustedVmSdk.inst()

@pytest.fixture(scope="module")
def default_alg_id():
    """Get default algorithm."""
    cc_type = ConfidentialVM.detect_cc_type()
    return cnf_default_alg[cc_type]

@pytest.fixture(scope="module")
def measurement_count():
    """Get measurement count."""
    cc_type = ConfidentialVM.detect_cc_type()
    return cnf_measurement_cnt[cc_type]

@pytest.fixture(scope="module")
def check_measurement():
    """Return checker for measurement."""
    cc_type = ConfidentialVM.detect_cc_type()
    return cnf_measurement_check[cc_type]

@pytest.fixture(scope="module")
def check_quote_valid_input():
    """Return checker for quote when input is valid."""
    cc_type = ConfidentialVM.detect_cc_type()
    return cnf_quote_check_valid_input[cc_type]

@pytest.fixture(scope="module")
def check_quote_invalid_input():
    """Return checker for quote when input is invalid."""
    cc_type = ConfidentialVM.detect_cc_type()
    return cnf_quote_check_invalid_input[cc_type]
