"""TDX specific test."""

import base64
from hashlib import sha384
import hashlib
import random
import pytest
from cctrusted_base.tcg import TcgAlgorithmRegistry, TcgImrEvent
from cctrusted_base.tdx.common import TDX_REPORTDATA_LEN
from cctrusted_base.tdx.quote import TdxQuote, TdxQuoteBody
from cctrusted_base.tdx.rtmr import TdxRTMR
from cctrusted_vm.sdk import CCTrustedVmSdk

def _replay_eventlog():
    """Get RTMRs from event log by replay."""
    rtmr_len = TdxRTMR.RTMR_LENGTH_BY_BYTES
    rtmr_cnt = TdxRTMR.RTMR_COUNT
    rtmrs = [bytearray(rtmr_len)] * rtmr_cnt
    event_logs = CCTrustedVmSdk.inst().get_eventlog().event_logs
    assert event_logs is not None
    for event in event_logs:
        if isinstance(event, TcgImrEvent):
            sha384_algo = sha384()
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
    imr = CCTrustedVmSdk.inst().get_measurement([imr_index, alg_id])
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
    """Make nonce for test.

    Returns:
        A nonce for test that is base64 encoded bytes reprensting a 64 bits unsigned integer.
    """
    # Generte a 64 bits unsigned integer randomly (range from 0 to 64 bits max).
    rand_num = random.randrange(0x0, 0xFFFFFFFFFFFFFFFF, 1)
    nonce = base64.b64encode(rand_num.to_bytes(8, "little"))
    return nonce

def _gen_valid_userdata():
    """Make userdata for test.

    Returns:
        User data that is base64 encoded bytes for test.
    """
    userdata = base64.b64encode(bytes("test user data", "utf-8"))
    return userdata

def _gen_invalid_base64_bytes():
    """Make bytes which is not base64 encoded.

    Returns:
        Bytes which is not base64 encoded.
    """
    invalid_chars = bytes("~!@#$%^&*()", "utf-8")
    invalid_bytes_len = random.randrange(1, len(invalid_chars), 1)
    invalid_bytes = bytes(random.choices(invalid_chars, k = invalid_bytes_len))
    return invalid_bytes

def _gen_invalid_nonce():
    """Make invalid nonce for test.

    Returns:
        Invalid nonce. e.g. A string that violates base64 encoding rule.
    """
    # Generate a string with some randomness for test.
    invalid_nonce = _gen_invalid_base64_bytes()
    return invalid_nonce

def _gen_invalid_userdata():
    """Make invalid userdata for test.

    Returns:
        Invalid user data. e.g. A string that violates base64 encoding rule.
    """
    # Generate a string with some randomness for test.
    invalid_userdata = _gen_invalid_base64_bytes()
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
    quote = CCTrustedVmSdk.inst().get_quote()
    _check_quote_rtmrs(quote)
    _check_quote_reportdata(quote)

    # Check RTMRs and REPORTDATA in the quote when "userdata is None".
    nonce = _gen_valid_nonce()
    quote = CCTrustedVmSdk.inst().get_quote(nonce)
    _check_quote_rtmrs(quote)
    _check_quote_reportdata(quote, nonce)

    # Check RTMRs and REPORTDATA in the quote when "nonce is None".
    userdata = _gen_valid_userdata()
    quote = CCTrustedVmSdk.inst().get_quote(None, userdata)
    _check_quote_rtmrs(quote)
    _check_quote_reportdata(quote, None, userdata)

    # Check RTMRs and REPORTDATA in the quote when "userdata is not None".
    nonce = _gen_valid_nonce()
    userdata = _gen_valid_userdata()
    quote = CCTrustedVmSdk.inst().get_quote(nonce, userdata)
    _check_quote_rtmrs(quote)
    _check_quote_reportdata(quote, nonce, userdata)

def tdx_check_quote_with_invalid_input():
    """Test get quote result when nonce and userdata are invalid."""

    # Check exception handling when "both nonce and user data are not base64 encoded".
    invalid_nonce = _gen_invalid_nonce()
    invalid_userdata = _gen_invalid_userdata()
    with pytest.raises(Exception) as excinfo:
        CCTrustedVmSdk.inst().get_quote(invalid_nonce, invalid_userdata)
        assert 'Non-base64 digit found' in str(excinfo.value)

    # Check exception handling when "nonce is not base64 encoded".
    invalid_nonce = _gen_invalid_nonce()
    userdata = _gen_valid_userdata()
    with pytest.raises(Exception) as excinfo:
        CCTrustedVmSdk.inst().get_quote(invalid_nonce, userdata)
        assert 'Non-base64 digit found' in str(excinfo.value)
    with pytest.raises(Exception) as excinfo:
        # Also check when userdata is None.
        CCTrustedVmSdk.inst().get_quote(invalid_nonce)
        assert 'Non-base64 digit found' in str(excinfo.value)

    # Check exception handling when "userdata is not base64 encoded".
    nonce = _gen_valid_nonce()
    invalid_userdata = _gen_invalid_userdata()
    with pytest.raises(Exception) as excinfo:
        CCTrustedVmSdk.inst().get_quote(nonce, invalid_userdata)
        assert 'Non-base64 digit found' in str(excinfo.value)
    with pytest.raises(Exception) as excinfo:
        # Also check when nonce is None.
        CCTrustedVmSdk.inst().get_quote(None, invalid_userdata)
        assert 'Non-base64 digit found' in str(excinfo.value)
