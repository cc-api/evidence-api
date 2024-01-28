"""Containing unit test cases for sdk class"""

from cctrusted_base.quote import Quote, QuoteData, QuoteSignature
from cctrusted_base.eventlog import EventLogs
from cctrusted_base.tcg import TcgEfiSpecIdEvent, TcgImrEvent, TcgPcClientImrEvent
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

def test_get_measurement_with_invalid_input(vm_sdk):
    """Test get_measurement() function with invalid input."""
    # calling get_measurement() with invalid IMR index
    measurement = vm_sdk.get_measurement([-1, 0xC])
    assert measurement is None

    # calling get_measurement() with invalid algorithm ID
    measurement = vm_sdk.get_measurement([0, None])
    assert measurement is not None

def test_get_measurement_with_valid_input(vm_sdk, check_measurement):
    """Test get_measurement() function with valid input."""
    count = vm_sdk.get_measurement_count()
    for index in range(count):
        alg = vm_sdk.get_default_algorithms()
        digest_obj = vm_sdk.get_measurement([index, alg.alg_id])
        assert digest_obj is not None
    check_measurement()

def test_get_eventlog_with_invalid_input(vm_sdk):
    """Test get_eventlog() function with invalid input."""
    # calling get_eventlog with count < 0
    with pytest.raises(ValueError):
        vm_sdk.get_eventlog(start=1, count=-1)

    # calling get_eventlog with start < 1
    with pytest.raises(ValueError):
        vm_sdk.get_eventlog(start=0)

def test_get_eventlog_with_valid_input(vm_sdk):
    """Test get_eventlog() funtion with valid input."""
    eventlog = vm_sdk.get_eventlog()

    # Check 1: the eventlog should not be None.
    assert eventlog is not None

    # Check 2: the object type should be correct.
    assert isinstance(eventlog, EventLogs)
    logs = eventlog.event_logs
    assert logs is not None
    assert isinstance(logs, list)
    event_count = 0
    for e in logs:
        event_count += 1
        assert isinstance(e, (TcgImrEvent, TcgPcClientImrEvent, TcgEfiSpecIdEvent))
    assert event_count == eventlog.count

def test_get_quote_with_valid_input(vm_sdk, check_quote_valid_input):
    """Test get_quote() function with valid input."""
    quote = vm_sdk.get_quote(None, None, None)

    # Check 1: the quote should not be None.
    assert quote is not None

    # Check 2: the object type should be correct.
    assert isinstance(quote, Quote)
    quoted_data = quote.get_quoted_data()
    assert quoted_data is not None
    assert isinstance(quoted_data, QuoteData)
    sigature_data = quote.get_sig()
    assert sigature_data is not None
    assert isinstance(sigature_data, QuoteSignature)

    # Check 3: platform specific check.
    check_quote_valid_input()

def test_get_quote_with_invalid_input(vm_sdk, check_quote_invalid_input):
    """Test get_quote() function with invalid input."""
    check_quote_invalid_input()
