package tdx

import "github.com/cc-api/cc-trusted-api/common/golang/cctrusted_base"

var _ cctrusted_base.Report = (*TdxReport)(nil)

type TdxReport struct {
	Quote *TdxQuote
}

func NewTdxReportFromBytes(b []byte) (*TdxReport, error) {
	t := &TdxReport{}
	err := t.InitFromBytes(b)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// IMRGroup implements cctrusted_base.Report.
func (t *TdxReport) IMRGroup() cctrusted_base.IMRGroup {
	group := cctrusted_base.IMRGroup{}
	group.MaxIndex = 3
	group.Group = make([]cctrusted_base.TcgDigest, 4)
	r0 := t.Quote.Body.Rtmr0
	group.Group[0] = NewRTMR(r0)
	r1 := t.Quote.Body.Rtmr1
	group.Group[1] = NewRTMR(r1)
	r2 := t.Quote.Body.Rtmr2
	group.Group[2] = NewRTMR(r2)
	r3 := t.Quote.Body.Rtmr3
	group.Group[3] = NewRTMR(r3)
	return group
}

// InitFromBytes implements cctrusted_base.Report.
func (t *TdxReport) InitFromBytes(b []byte) (err error) {
	t.Quote, err = NewTdxQuote(b)
	return err
}

func (t *TdxReport) Dump(format cctrusted_base.QuoteDumpFormat) {
	t.Quote.Dump(format, "")
}
