package cctrusted_base

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultIMARecorder(t *testing.T) {
	r := &DefaultIMARecorder{}
	r.ProbeIMARecorder()
	l, err := r.FullIMALog()
	assert.Nil(t, err)
	assert.NotNil(t, l)
}
