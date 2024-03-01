package cctrusted_base

type QuoteDumpFormat string
type DeviceVersion string

const (
	QuoteDumpFormatRaw   QuoteDumpFormat = "raw"
	QuoteDumpFormatHuman QuoteDumpFormat = "human"
)

type IMRGroup struct {
	MaxIndex int
	Group    []TcgDigest
}

type Report interface {
	InitFromBytes([]byte) error
	IMRGroup() IMRGroup
	Dump(QuoteDumpFormat)
}
