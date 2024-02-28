package tdx

import "github.com/cc-api/cc-trusted-api/common/golang/cctrusted_base"

const (
	RTMRMaxIndex = 3
)

func NewRTMR(digest [48]byte) cctrusted_base.TcgDigest {
	d := cctrusted_base.TcgDigest{}
	d.AlgID = cctrusted_base.TPM_ALG_SHA384
	d.Hash = digest[:]
	return d
}
