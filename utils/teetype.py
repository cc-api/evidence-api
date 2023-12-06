from enum import Enum

class TeeType(Enum):
    TDX_NATIVE = 1
    TDX_vTPM = 2
    SEV_NATIVE = 3
    SEV_vTPM = 4
    SGX = 5
    TEE_OTHER = 6

    @staticmethod
    def check_tee_type():
        # check if in TDX native/SEV native/TDX vTPM/SEV vTPM env etc,

        # sample run in TDX env
        return TeeType.TDX_NATIVE