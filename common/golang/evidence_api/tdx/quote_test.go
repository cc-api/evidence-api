package tdx

import (
	"bufio"
	"bytes"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/cc-api/evidence-api/common/golang/evidence_api"

	"github.com/stretchr/testify/assert"
)

func TestQuoteDumpHuman(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)

	quoteBin, err := os.ReadFile("../test_data/quote.bin")
	assert.Nil(t, err)
	expected, err := os.ReadFile("../test_data/formated_quote.txt")
	assert.Nil(t, err)

	quote, err := NewTdxQuote(quoteBin)
	assert.Nil(t, err)
	quote.Dump(evidence_api.QuoteDumpFormatHuman, "")
	r := strings.NewReader(buf.String())
	s := bufio.NewScanner(r)

	r2 := strings.NewReader(string(expected))
	s2 := bufio.NewScanner(r2)

	for s.Scan() && s2.Scan() {
		assert.EqualValues(t, s.Text()[20:], s2.Text()[20:])
	}

}
