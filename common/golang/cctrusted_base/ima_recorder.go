package cctrusted_base

import "os"

const (
	IMA_DATA_FILE = "/sys/kernel/security/integrity/ima/ascii_runtime_measurements"
)

type IMARecorder interface {
	FullIMALog() ([]byte, error)
	ProbeIMARecorder() error
}

var _ IMARecorder = (*DefaultIMARecorder)(nil)

type DefaultIMARecorder struct {
	recoder   string
	rawIMALog []byte
}

// ProbeRecorder implements IMARecorder.
func (r *DefaultIMARecorder) ProbeIMARecorder() error {
	r.recoder = IMA_DATA_FILE
	if _, err := os.Stat(r.recoder); err != nil {
		return err
	}
	return nil
}

// FullIMALog implements IMARecorder.
func (r *DefaultIMARecorder) FullIMALog() ([]byte, error) {
	log, err := os.ReadFile(r.recoder)
	if err != nil {
		return nil, err
	}
	r.rawIMALog = log
	return r.rawIMALog, nil
}
