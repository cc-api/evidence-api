"""TDX specific test."""

import base64
import hashlib
import logging
import os
import random
import pytest
from cctrusted_base.api import CCTrustedApi
from cctrusted_base.eventlog import EventLogs
from cctrusted_base.tcg import TcgAlgorithmRegistry, TcgEventType
from cctrusted_base.tdx.common import TDX_REPORTDATA_LEN
from cctrusted_base.tdx.quote import TdxQuote, TdxQuoteBody
from cctrusted_base.tdx.rtmr import TdxRTMR
from cctrusted_vm.sdk import CCTrustedVmSdk

LOG = logging.getLogger(__name__)

def _replay_eventlog():
    """Get RTMRs from event log by replay."""
    rtmr_len = TdxRTMR.RTMR_LENGTH_BY_BYTES
    rtmr_cnt = TdxRTMR.RTMR_COUNT
    rtmrs = [bytearray(rtmr_len)] * rtmr_cnt
    event_logs = CCTrustedVmSdk.inst().get_cc_eventlog().event_logs
    assert event_logs is not None
    for event in event_logs:
        if event.event_type != TcgEventType.EV_NO_ACTION:
            sha384_algo = hashlib.sha384()
            sha384_algo.update(rtmrs[event.imr_index] + event.digests[0].hash)
            rtmrs[event.imr_index] = sha384_algo.digest()
    return rtmrs

def _check_imr(imr_index: int, alg_id: int, rtmr: bytes):
    """Check individual IMR.
    Compare the 4 IMR hash with the hash derived by replay event log. They are
    expected to be same.
    Args:
        imr_index: an integer specified the IMR index.
        alg_id: an integer specified the hash algorithm.
        rtmr: bytes of RTMR data for comparison.
    """
    assert 0 <= imr_index < TdxRTMR.RTMR_COUNT
    assert rtmr is not None
    assert alg_id == TcgAlgorithmRegistry.TPM_ALG_SHA384
    imr = CCTrustedVmSdk.inst().get_cc_measurement([imr_index, alg_id])
    assert imr is not None
    digest_obj = imr.digest(alg_id)
    assert digest_obj is not None
    digest_alg_id = digest_obj.alg.alg_id
    assert digest_alg_id == TcgAlgorithmRegistry.TPM_ALG_SHA384
    digest_hash = digest_obj.hash
    assert digest_hash is not None
    assert digest_hash == rtmr, f"rtmr {rtmr.hex()} doesn't equal digest {digest_hash.hex()}"

def tdx_check_measurement_imrs():
    """Test measurement result.
    The test is done by compare the measurement register against the value
    derived by replay eventlog.
    """
    alg = CCTrustedVmSdk.inst().get_default_algorithms()
    rtmrs = _replay_eventlog()
    _check_imr(0, alg.alg_id, rtmrs[0])
    _check_imr(1, alg.alg_id, rtmrs[1])
    _check_imr(2, alg.alg_id, rtmrs[2])
    _check_imr(3, alg.alg_id, rtmrs[3])

def _gen_valid_nonce():
    """Generate nonce for test.

    Returns:
        A nonce for test that is base64 encoded bytes reprensting a 64 bits unsigned integer.
    """
    # Generte a 64 bits unsigned integer randomly (range from 0 to 64 bits max).
    rand_num = random.randrange(0x0, 0xFFFFFFFFFFFFFFFF, 1)
    nonce = base64.b64encode(rand_num.to_bytes(8, "little"))
    LOG.info("_gen_valid_nonce: %s", nonce.hex())
    return nonce

def _gen_valid_userdata():
    """Generate userdata for test.

    Returns:
        User data that is base64 encoded bytes for test.
    """
    userdata = base64.b64encode(bytes("test user data", "utf-8"))
    LOG.info("_gen_valid_userdata: %s", userdata.hex())
    return userdata

def _gen_invalid_base64_bytes():
    """Generate bytes which is not base64 encoded.

    Returns:
        Bytes which is not base64 encoded.
    """
    invalid_chars = bytes("~!@#$%^&*()", "utf-8")
    invalid_bytes_len = random.randrange(1, len(invalid_chars), 1)
    invalid_bytes = bytes(random.choices(invalid_chars, k = invalid_bytes_len))
    LOG.info("_gen_invalid_base64_bytes: %s", invalid_bytes.hex())
    return invalid_bytes

def _gen_invalid_nonce():
    """Generate invalid nonce for test.

    Returns:
        Invalid nonce. e.g. A string that violates base64 encoding rule.
    """
    # Generate a string with some randomness for test.
    invalid_nonce = _gen_invalid_base64_bytes()
    LOG.info("_gen_invalid_nonce: %s", invalid_nonce.hex())
    return invalid_nonce

def _gen_invalid_userdata():
    """Generate invalid userdata for test.

    Returns:
        Invalid user data. e.g. A string that violates base64 encoding rule.
    """
    # Generate a string with some randomness for test.
    invalid_userdata = _gen_invalid_base64_bytes()
    LOG.info("_gen_invalid_userdata: %s", invalid_userdata.hex())
    return invalid_userdata

def _check_quote_rtmrs(quote):
    """Check the RTMRs in quote result.
    The test is done by compare the RTMRs in quote body against the value
    derived by replay eventlog.
    """
    assert quote is not None and isinstance(quote, TdxQuote)
    body = quote.body
    assert body is not None and isinstance(body, TdxQuoteBody)
    rtmrs = _replay_eventlog()
    assert body.rtmr0 == rtmrs[0], "RTMR0 doesn't equal the replay from event log!"
    assert body.rtmr1 == rtmrs[1], "RTMR1 doesn't equal the replay from event log!"
    assert body.rtmr2 == rtmrs[2], "RTMR2 doesn't equal the replay from event log!"
    assert body.rtmr3 == rtmrs[3], "RTMR3 doesn't equal the replay from event log!"

def _check_quote_reportdata(quote, nonce=None, userdata=None):
    """Check the userdata in quote result."""
    assert quote is not None and isinstance(quote, TdxQuote)
    assert quote.cc_type == CCTrustedApi.TYPE_CC_TDX
    body = quote.body
    assert body is not None and isinstance(body, TdxQuoteBody)
    out_data = body.reportdata
    assert out_data is not None
    expectation = None
    if nonce is None and userdata is None:
        expectation = bytes([0]) * TDX_REPORTDATA_LEN
    else:
        hash_algo = hashlib.sha512()
        if nonce is not None:
            hash_algo.update(bytes(base64.b64decode(nonce)))
        if userdata is not None:
            hash_algo.update(bytes(base64.b64decode(userdata)))
        expectation = hash_algo.digest()
    assert expectation == out_data

def tdx_check_quote_with_valid_input():
    """Test get quote result when nonce and userdata are valid."""

    # Check RTMRs and REPORTDATA in the quote when "both nonce and userdata are None".
    quote = CCTrustedVmSdk.inst().get_cc_report()
    _check_quote_rtmrs(quote)
    _check_quote_reportdata(quote)

    # Check RTMRs and REPORTDATA in the quote when "userdata is None".
    nonce = _gen_valid_nonce()
    quote = CCTrustedVmSdk.inst().get_cc_report(nonce)
    _check_quote_rtmrs(quote)
    _check_quote_reportdata(quote, nonce)

    # Check RTMRs and REPORTDATA in the quote when "nonce is None".
    userdata = _gen_valid_userdata()
    quote = CCTrustedVmSdk.inst().get_cc_report(None, userdata)
    _check_quote_rtmrs(quote)
    _check_quote_reportdata(quote, None, userdata)

    # Check RTMRs and REPORTDATA in the quote when "userdata is not None".
    nonce = _gen_valid_nonce()
    userdata = _gen_valid_userdata()
    quote = CCTrustedVmSdk.inst().get_cc_report(nonce, userdata)
    _check_quote_rtmrs(quote)
    _check_quote_reportdata(quote, nonce, userdata)

def tdx_check_quote_with_invalid_input():
    """Test get quote result when nonce and userdata are invalid."""

    # Check exception handling when "both nonce and user data are not base64 encoded".
    invalid_nonce = _gen_invalid_nonce()
    invalid_userdata = _gen_invalid_userdata()
    with pytest.raises(Exception) as excinfo:
        CCTrustedVmSdk.inst().get_cc_report(invalid_nonce, invalid_userdata)
        assert 'Non-base64 digit found' in str(excinfo.value)

    # Check exception handling when "nonce is not base64 encoded".
    invalid_nonce = _gen_invalid_nonce()
    userdata = _gen_valid_userdata()
    with pytest.raises(Exception) as excinfo:
        CCTrustedVmSdk.inst().get_cc_report(invalid_nonce, userdata)
        assert 'Non-base64 digit found' in str(excinfo.value)
    with pytest.raises(Exception) as excinfo:
        # Also check when userdata is None.
        CCTrustedVmSdk.inst().get_cc_report(invalid_nonce)
        assert 'Non-base64 digit found' in str(excinfo.value)

    # Check exception handling when "userdata is not base64 encoded".
    nonce = _gen_valid_nonce()
    invalid_userdata = _gen_invalid_userdata()
    with pytest.raises(Exception) as excinfo:
        CCTrustedVmSdk.inst().get_cc_report(nonce, invalid_userdata)
        assert 'Non-base64 digit found' in str(excinfo.value)
    with pytest.raises(Exception) as excinfo:
        # Also check when nonce is None.
        CCTrustedVmSdk.inst().get_cc_report(None, invalid_userdata)
        assert 'Non-base64 digit found' in str(excinfo.value)

def _gen_valid_eventlog():
    """Generate valid eventlog for test."""
    # One valid input could be current eventlog.
    eventlog = CCTrustedVmSdk.inst().get_cc_eventlog()
    assert eventlog is not None
    return eventlog

def _gen_invalid_eventlog():
    """Generate invalid eventlog for test."""
    boot_time_data_len = random.randrange(0, 512, 1)
    boot_time_data = os.urandom(boot_time_data_len)
    LOG.info("_gen_invalid_eventlog boot_time_data: %s", boot_time_data.hex())
    run_time_data_len = random.randrange(0, 512, 1)
    run_time_data = os.urandom(run_time_data_len)
    LOG.info("_gen_invalid_eventlog run_time_data: %s", run_time_data.hex())
    invalid_eventlog = EventLogs(boot_time_data, run_time_data)
    return invalid_eventlog

def tdx_check_replay_eventlog_with_valid_input():
    """Test replay_eventlog with valid input."""
    eventlog = _gen_valid_eventlog()
    replay_result = CCTrustedVmSdk.inst().replay_cc_eventlog(eventlog)
    assert replay_result is not None and 0 < len(replay_result) <= TdxRTMR.RTMR_COUNT
    alg = CCTrustedVmSdk.inst().get_default_algorithms().alg_id
    for imr_idx, replayed_values in replay_result.items():
        assert 0 <= imr_idx < TdxRTMR.RTMR_COUNT
        assert replayed_values is not None and isinstance(replayed_values, dict)
        v = replayed_values[alg]
        assert v is not None
        _check_imr(imr_idx, alg, v)

def tdx_check_replay_eventlog_with_invalid_input():
    """Test replay_eventlog with invalid input."""

    # Check the replay result should be None when input None.
    replay_result = CCTrustedVmSdk.inst().replay_cc_eventlog(None)
    assert replay_result is None

    # Check the replay result when input invalid eventlog.
    invalid_eventlog = _gen_invalid_eventlog()
    replay_result = CCTrustedVmSdk.inst().replay_cc_eventlog(invalid_eventlog)
    assert replay_result is not None
    assert 0 == len(replay_result)
