package cctrusted_base

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEventLog(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)

	elBin, err := os.ReadFile("./test_data/ccel_data.bin")
	assert.Nil(t, err)
	imaBin, err := os.ReadFile("./test_data/ima_log.bin")
	assert.Nil(t, err)
	expected, err := os.ReadFile("./test_data/formated_el.txt")
	assert.Nil(t, err)
	expectedImrs := map[int]string{
		0: "57518d2150d2a7a402a5e7370db779474db869bed15d83ab02467ed90646d8b9b8e5d34175f79ff00de3c346a7ad9f6a",
		1: "6cef5b111a32290d4dbd88af175676172d31894ed3a71e567ef51c8c0d84309bb589e5b6535c9cc6dbd76a566d59c629",
		2: "0ba032df5987b49b7c36aa314b8c599f3daf16ad1d1b93c824f8a2d69522139b4021f6f256be23d80d119d36bff8e7e4",
	}

	el := NewEventLogger(elBin, imaBin, TCG_PCCLIENT_FORMAT)
	el.Parse()
	el.Dump(QuoteDumpFormatHuman)

	r := strings.NewReader(buf.String())
	s := bufio.NewScanner(r)

	r2 := strings.NewReader(string(expected))
	s2 := bufio.NewScanner(r2)

	for s.Scan() && s2.Scan() {
		assert.EqualValues(t, s.Text()[20:], s2.Text()[20:])
	}

	replay := el.Replay()
	for idx, elem := range replay {
		for k, v := range elem {
			assert.Equal(t, k, TPM_ALG_SHA384)
			assert.EqualValues(t, hex.EncodeToString(v), expectedImrs[idx])
		}
	}

}
