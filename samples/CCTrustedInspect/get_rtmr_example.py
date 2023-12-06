import sys
sys.path.append("../..")

from vmsdk.python.cctrusted.measurement import Measurement

rtmrs = Measurement.get_measurement()

rtmrs.dump_rtmrs()
rtmrs.dump_rtmrs_by_index(2)

