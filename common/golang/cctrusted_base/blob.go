package cctrusted_base

import (
	"encoding/binary"
	"fmt"
	"log"
	"unicode"
)

// BinaryBlob helps parse raw bytes into structure data
type BinaryBlob struct {
	Binary []byte
	Base   int
}

func NewBinaryBlob(b []byte, base int) BinaryBlob {
	return BinaryBlob{
		Binary: b,
		Base:   base,
	}
}

func (b *BinaryBlob) ParseUint8(start int) (uint8, int) {
	return b.Binary[start], start + 1
}

func (b *BinaryBlob) ParseUint16(start int) (uint16, int) {
	val := binary.LittleEndian.Uint16(b.Binary[start : start+2])
	return val, start + 2
}

func (b *BinaryBlob) ParseUint32(start int) (uint32, int) {
	val := binary.LittleEndian.Uint32(b.Binary[start : start+4])
	return val, start + 4
}

func (b *BinaryBlob) ParseUint64(start int) (uint64, int) {
	val := binary.LittleEndian.Uint64(b.Binary[start : start+8])
	return val, start + 8
}

func (b *BinaryBlob) ParseBytes(start, count int) ([]byte, int) {
	return b.Binary[start : start+count], start + count
}

func (b *BinaryBlob) Dump() {
	l := log.Default()
	index := 0
	length := len(b.Binary)
	baseAddr := ""
	hexStr := ""
	readableStr := ""
	for ; index < length; index++ {
		if index%16 == 0 {
			if len(baseAddr) != 0 {
				l.Println(baseAddr, hexStr, readableStr)
			}
			baseAddr = fmt.Sprintf("%08x", b.Base+index/16*16)
			hexStr = ""
			readableStr = ""
		}
		chr := b.Binary[index]
		hexStr += fmt.Sprintf("%02x ", chr)
		switch chr {
		case 0xC, 0xB, 0xA, 0xD, 0x9:
			readableStr += "."
		default:

			if !unicode.IsPrint(rune(chr)) {
				readableStr += "."
			} else {
				readableStr += string(chr)
			}
		}
	}
	if index%16 != 0 {
		for i := 0; i < 16-index%16; i++ {
			hexStr += "   "
		}
		l.Println(baseAddr, hexStr, readableStr)
	} else if index == length {
		l.Println(baseAddr, hexStr, readableStr)
	}
}
