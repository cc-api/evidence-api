import hashlib
import logging
import struct

import sys
sys.path.append("../../..")
from utils.tdx.utility import DeviceNode
from utils.tdx.binaryblob import BinaryBlob
from utils.teetype import TeeType

__author__ = ""

LOG = logging.getLogger(__name__)

class Quote(BinaryBlob):

    def __init__(self, data, device_node=None):
        logging.basicConfig(level=logging.DEBUG, format='%(message)s')
        super().__init__(data)
        # auxiliary fileds
        if device_node is None:
            device_node = DeviceNode()
        self.device_node = device_node

    @staticmethod
    def check_tee_type():
        # check if in TDX native/SEV native/TDX vTPM/SEV vTPM env etc,
        return TeeType.TDX_NATIVE

    @staticmethod
    def get_quote(nonce=None, data=None):
        report_data = None

        teeEnv = TeeType.check_tee_type()

        # TDX native env
        if teeEnv == TeeType.TDX_NATIVE:
            if nonce is None and data is None:
                LOG.info("No report data, generating default quote")
            else:
                LOG.info("Calculate report data by nonce and user data")
                hash_algo = hashlib.sha512()
                if nonce is not None:
                    hash_algo.update(bytes(nonce))
                if data is not None:
                    hash_algo.update(bytes(data))
                report_data = hash_algo.digest()
            device_node = DeviceNode()
            tdquote_bytes = device_node.get_tdquote_bytes(report_data)
            if tdquote_bytes is not None:
                quote = Quote(tdquote_bytes, device_node)
                return quote
            return None

        if teeEnv == TeeType.SEV_NATIVE:
            pass

        if teeEnv == TeeType.TDX_vTPM:
            pass

        if teeEnv == TeeType.SEV_vTPM:
            pass

        if teeEnv == TeeType.SGX:
            pass

        if teeEnv == TeeType.TEE_OTHER:
            pass   