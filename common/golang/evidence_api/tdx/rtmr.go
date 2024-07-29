package tdx

import "github.com/cc-api/evidence-api/common/golang/evidence_api"

const (
	RTMRMaxIndex = 3
)

func NewRTMR(digest [48]byte) evidence_api.TcgDigest {
	d := evidence_api.TcgDigest{}
	d.AlgID = evidence_api.TPM_ALG_SHA384
	d.Hash = digest[:]
	return d
}
