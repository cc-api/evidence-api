"""Containing unit test cases for sdk class"""

import pytest
from cctrusted_vm import CCTrustedVmSdk

class TestCCTrustedVmSdk():
    """Unit tests for CCTrustedVmSdk class."""

    def test_get_default_algorithms(self):
        """Test get_default_algorithms() function."""
        algo = CCTrustedVmSdk.inst().get_default_algorithms()
        assert algo is not None

    def test_get_measurement_count(self):
        """Test get_measurement_count() function."""
        count = CCTrustedVmSdk.inst().get_measurement_count()
        assert count is not None

    def test_get_measurement_with_invalid_input(self):
        """Test get_measurement() function with invalid input."""
        # calling get_measurement() with invalid IMR index
        measurement = CCTrustedVmSdk.inst().get_measurement([-1, 0xC])
        assert measurement is None

        # calling get_measurement() with invalid algorithm ID
        measurement = CCTrustedVmSdk.inst().get_measurement([0, None])
        assert measurement is not None

    def test_get_measurement_with_valid_input(self):
        """Test get_measurement() function with valid input."""
        count = CCTrustedVmSdk.inst().get_measurement_count()
        for index in range(count):
            alg = CCTrustedVmSdk.inst().get_default_algorithms()
            digest_obj = CCTrustedVmSdk.inst().get_measurement([index, alg.alg_id])
            assert digest_obj is not None

    def test_get_eventlog_with_invalid_input(self):
        """Test get_eventlog() function with invalid input."""
        # calling get_eventlog with count < 0
        with pytest.raises(ValueError):
            CCTrustedVmSdk.inst().get_eventlog(start=1, count=-1)

        # calling get_eventlog with start < 1
        with pytest.raises(ValueError):
            CCTrustedVmSdk.inst().get_eventlog(start=0)

    def test_get_eventlog_with_valid_input(self):
        """Test get_eventlog() funtion with valid input."""
        event_logs = CCTrustedVmSdk.inst().get_eventlog()
        assert event_logs is not None

    def test_get_quote_with_valid_input(self):
        """Test get_quote() function with valid input."""
        quote = CCTrustedVmSdk.inst().get_quote(None, None, None)
        assert quote is not None
