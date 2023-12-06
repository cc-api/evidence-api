import sys
sys.path.append("../..")

from vmsdk.python.cctrusted.quote import Quote

nonce = bytes("test_nonce",'utf-8')
data = bytes("test_data",'utf-8')
tdquote = Quote.get_quote(nonce,data)
tdquote.dump()
