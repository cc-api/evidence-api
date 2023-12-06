import logging

import sys
sys.path.append("../../..")
from utils.tdx.tdreport import TdReport
from utils.tdx.binaryblob import BinaryBlob
from utils.teetype import TeeType
from utils.tdx.actor import  TDEventLogActor
from utils.tdx.ccel import CCEL

__author__ = ""

LOG = logging.getLogger(__name__)

class Eventlog(BinaryBlob):
    def __init__(self, data):
        logging.basicConfig(level=logging.DEBUG, format='%(message)s')
        super().__init__(data)

    @staticmethod
    def get_eventlog():
        teeEnv = TeeType.check_tee_type()

        # TDX native env
        if teeEnv == TeeType.TDX_NATIVE:
            ccelobj = CCEL.create_from_acpi_file()
            actor = TDEventLogActor(ccelobj.log_area_start_address,ccelobj.log_area_minimum_length)            
            return actor

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