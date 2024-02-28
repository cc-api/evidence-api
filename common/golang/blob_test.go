package cctrusted_base

import (
	"bufio"
	"bytes"
	"log"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBlobDump(t *testing.T) {
	content := []byte("2 67c70809bd405ea82081e8f1eb2ca16108bce307f5f139492da641e08e07ec99e2163649f29323a5f5963fe07bb06cc6 ima-ng sha384:cd01ce7f8d1a658f8fdaf33bfb18a7bf9bc3d45386f16be3caf22ef9cb32a26ec53d8b8b74c76b94b744bdf191506cb3 boot_aggregate")
	expected := []string{
		"00000000 32 20 36 37 63 37 30 38 30 39 62 64 34 30 35 65  2 67c70809bd405e",
		"00000010 61 38 32 30 38 31 65 38 66 31 65 62 32 63 61 31  a82081e8f1eb2ca1",
		"00000020 36 31 30 38 62 63 65 33 30 37 66 35 66 31 33 39  6108bce307f5f139",
		"00000030 34 39 32 64 61 36 34 31 65 30 38 65 30 37 65 63  492da641e08e07ec",
		"00000040 39 39 65 32 31 36 33 36 34 39 66 32 39 33 32 33  99e2163649f29323",
		"00000050 61 35 66 35 39 36 33 66 65 30 37 62 62 30 36 63  a5f5963fe07bb06c",
		"00000060 63 36 20 69 6d 61 2d 6e 67 20 73 68 61 33 38 34  c6 ima-ng sha384",
		"00000070 3a 63 64 30 31 63 65 37 66 38 64 31 61 36 35 38  :cd01ce7f8d1a658",
		"00000080 66 38 66 64 61 66 33 33 62 66 62 31 38 61 37 62  f8fdaf33bfb18a7b",
		"00000090 66 39 62 63 33 64 34 35 33 38 36 66 31 36 62 65  f9bc3d45386f16be",
		"000000a0 33 63 61 66 32 32 65 66 39 63 62 33 32 61 32 36  3caf22ef9cb32a26",
		"000000b0 65 63 35 33 64 38 62 38 62 37 34 63 37 36 62 39  ec53d8b8b74c76b9",
		"000000c0 34 62 37 34 34 62 64 66 31 39 31 35 30 36 63 62  4b744bdf191506cb",
		"000000d0 33 20 62 6f 6f 74 5f 61 67 67 72 65 67 61 74 65  3 boot_aggregate",
	}

	var buf bytes.Buffer
	log.SetOutput(&buf)
	blob := NewBinaryBlob(content, 0)
	blob.Dump()

	r := strings.NewReader(buf.String())
	s := bufio.NewScanner(r)
	index := 0
	for s.Scan() {
		assert.Contains(t, s.Text(), expected[index])
		index++
	}
}
