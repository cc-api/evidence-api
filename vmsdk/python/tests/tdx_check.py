"""TDX specific test."""

from hashlib import sha384
from cctrusted_base.tcg import TcgAlgorithmRegistry, TcgEventType
from cctrusted_base.tdx.quote import TdxQuote, TdxQuoteBody
from cctrusted_base.tdx.rtmr import TdxRTMR
from cctrusted_vm.sdk import CCTrustedVmSdk

def _replay_eventlog():
    """Get RTMRs from event log by replay."""
    rtmr_len = TdxRTMR.RTMR_LENGTH_BY_BYTES
    rtmr_cnt = TdxRTMR.RTMR_COUNT
    rtmrs = [bytearray(rtmr_len)] * rtmr_cnt
    event_logs = CCTrustedVmSdk.inst().get_cc_eventlog().event_logs
    assert event_logs is not None
    for event in event_logs:
        if event.event_type != TcgEventType.EV_NO_ACTION:
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
    imr = CCTrustedVmSdk.inst().get_cc_measurement([imr_index, alg_id])
    assert imr is not None
    digest_obj = imr.digest(alg_id)
    assert digest_obj is not None
    digest_alg_id = digest_obj.alg.alg_id
    assert digest_alg_id == TcgAlgorithmRegistry.TPM_ALG_SHA384
    digest_hash = digest_obj.hash
    assert digest_hash is not None
    assert digest_hash == rtmr, \
        f"rtmr {rtmr.hex()} doesn't equal digest {digest_hash.hex()}"

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

def tdx_check_quote_rtmrs():
    """Test quote result.
    The test is done by compare the RTMRs in quote body against the value
    derived by replay eventlog.
    """
    quote = CCTrustedVmSdk.inst().get_cc_report()
    assert quote is not None
    assert isinstance(quote, TdxQuote)
    body = quote.body
    assert body is not None
    assert isinstance(body, TdxQuoteBody)
    rtmrs = _replay_eventlog()
    assert body.rtmr0 == rtmrs[0], \
        "RTMR0 doesn't equal the replay from event log!"
    assert body.rtmr1 == rtmrs[1], \
        "RTMR1 doesn't equal the replay from event log!"
    assert body.rtmr2 == rtmrs[2], \
        "RTMR2 doesn't equal the replay from event log!"
    assert body.rtmr3 == rtmrs[3], \
        "RTMR3 doesn't equal the replay from event log!"
