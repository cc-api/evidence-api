"""Containing unit test cases for sdk class"""

from cctrusted_base.ccreport import CcReport, CcReportData, CcReportSignature
from cctrusted_base.tcg import TcgImrEvent, TcgPcClientImrEvent
from cctrusted_base.tcgcel import TcgTpmsCelEvent
import pytest

def test_get_default_algorithms(vm_sdk, default_alg_id):
    """Test get_default_algorithms() function."""
    algo = vm_sdk.get_default_algorithms()
    assert algo is not None
    assert algo.alg_id == default_alg_id

def test_get_measurement_count(vm_sdk, measurement_count):
    """Test get_measurement_count() function."""
    count = vm_sdk.get_measurement_count()
    assert count is not None
    assert count == measurement_count

def test_get_cc_measurement_with_invalid_input(vm_sdk):
    """Test get_cc_measurement() function with invalid input."""
    # calling get_cc_measurement() with invalid IMR index
    measurement = vm_sdk.get_cc_measurement([-1, 0xC])
    assert measurement is None

    # calling get_cc_measurement() with invalid algorithm ID
    measurement = vm_sdk.get_cc_measurement([0, None])
    assert measurement is not None

def test_get_cc_measurement_with_valid_input(vm_sdk, check_measurement):
    """Test get_cc_measurement() function with valid input."""
    count = vm_sdk.get_measurement_count()
    for index in range(count):
        alg = vm_sdk.get_default_algorithms()
        digest_obj = vm_sdk.get_cc_measurement([index, alg.alg_id])
        assert digest_obj is not None
    check_measurement()

def test_get_cc_eventlog_with_invalid_input(vm_sdk):
    """Test get_cc_eventlog() function with invalid input.

    The test logic currently has an assumption that the return result of get_cc_eventlog
    doesn't change if the input parameters are the same within a short period of time.
    """
    event_num = len(vm_sdk.get_cc_eventlog())
    idx_min = 0
    idx_max = event_num - 1
    cnt_min = 1
    cnt_max = event_num

    # calling get_cc_eventlog with invalid "start"
    with pytest.raises(ValueError):
        invalid_start = idx_min - 1
        vm_sdk.get_cc_eventlog(start=invalid_start, count=1)
    with pytest.raises(ValueError):
        invalid_start = idx_max + 2
        vm_sdk.get_cc_eventlog(start=invalid_start, count=1)
    # a special case works as current design
    invalid_start = idx_max + 1
    eventlog = vm_sdk.get_cc_eventlog(start=invalid_start, count=1)
    assert len(eventlog) == 0

    # calling get_cc_eventlog with invalid "count"
    with pytest.raises(ValueError):
        invalid_count = cnt_min - 1
        vm_sdk.get_cc_eventlog(start=idx_min, count=invalid_count)
    with pytest.raises(ValueError):
        invalid_count = cnt_max + 1
        vm_sdk.get_cc_eventlog(start=idx_min, count=invalid_count)
    with pytest.raises(ValueError):
        vm_sdk.get_cc_eventlog(start=idx_max, count=2)

def test_get_cc_eventlog_with_valid_input(vm_sdk):
    """Test get_eventlog() funtion with valid input."""
    eventlog = vm_sdk.get_cc_eventlog()

    # Check 1: the eventlog should not be None.
    assert eventlog is not None

    # Check 2: the object type should be correct.
    assert isinstance(eventlog, list)
    event_count = 0
    for e in eventlog:
        event_count += 1
        assert isinstance(e, (TcgImrEvent, TcgPcClientImrEvent, TcgTpmsCelEvent))

def test_get_cc_report_with_valid_input(vm_sdk, check_quote_valid_input):
    """Test get_cc_report() function with valid input."""
    quote = vm_sdk.get_cc_report(None, None, None)

    # Check 1: the quote should not be None.
    assert quote is not None

    # Check 2: the object type should be correct.
    assert isinstance(quote, CcReport)
    quoted_data = quote.get_quoted_data()
    assert quoted_data is not None
    assert isinstance(quoted_data, CcReportData)
    sigature_data = quote.get_sig()
    assert sigature_data is not None
    assert isinstance(sigature_data, CcReportSignature)

    # Check 3: platform specific check.
    check_quote_valid_input()

def test_get_cc_report_with_invalid_input(check_quote_invalid_input):
    """Test get_cc_report() function with invalid input."""
    check_quote_invalid_input()

def test_replay_cc_eventlog_with_valid_input(check_replay_eventlog_valid_input):
    """Test replay_cc_eventlog() function with valid input."""
    check_replay_eventlog_valid_input()

def test_replay_cc_eventlog_with_invalid_input(check_replay_eventlog_invalid_input):
    """Test replay_cc_eventlog() function with invalid input."""
    check_replay_eventlog_invalid_input()
