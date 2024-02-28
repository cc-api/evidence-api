package tdx

import (
	"encoding/binary"

	"github.com/cc-api/cc-trusted-api/common/golang/cctrusted_base"
)

// Common definition for Intel TDX.

type OperatorName string
type QgsMsgType uint32
type AttestationKeyType uint16
type TeeType uint32

const (
	TDX_VERSION_1_0        cctrusted_base.DeviceVersion = "1.0"
	TDX_VERSION_1_0_DEVICE string                       = "/dev/tdx-guest"

	TDX_VERSION_1_5        cctrusted_base.DeviceVersion = "1.5"
	TDX_VERSION_1_5_DEVICE string                       = "/dev/tdx_guest"

	TDX_QUOTE_VERSION_4 = 4
	TDX_QUOTE_VERSION_5 = 5

	// The length of the reportdata
	TD_REPORTDATA_LEN = 64
	// The length of the tdreport
	TD_REPORT_LEN = 1024
	// The length of the report/quote
	TDX_QUOTE_LEN = 4 * 4096

	// Allowd Operation
	// Get td report, td report is a structure consisting of some
	// info from tdx module and td vm. Being signed by the Intel PCS,
	// it becomes the report for remote attestation.
	GetTdReport OperatorName = "GetTdReport"
	// Get td quote
	GetQuote OperatorName = "GetQuote"

	GetQuoteReq  QgsMsgType = 0
	GetQuoteResp QgsMsgType = 1

	AttestationKeyType_ECDSA_P256 AttestationKeyType = 2
	AttestationKeyType_ECDSA_P384 AttestationKeyType = 3

	TEE_SGX TeeType = 0x00000000
	TEE_TDX TeeType = 0x00000081
)

func (t AttestationKeyType) String() string {
	switch t {
	case AttestationKeyType_ECDSA_P256:
		return "AttestationKeyType.ECDSA_P256"
	case AttestationKeyType_ECDSA_P384:
		return "AttestationKeyType.ECDSA_P384"
	}
	return ""
}

func (t TeeType) String() string {
	switch t {
	case TEE_SGX:
		return "TeeType.TEE_SGX"
	case TEE_TDX:
		return "TeeType.TEE_TDX"
	}
	return ""
}

type TDXDeviceSpec struct {
	Version          cctrusted_base.DeviceVersion
	DevicePath       string
	AllowedOperation map[OperatorName]uintptr
}

var (
	TdxDeviceSpecs = map[string]TDXDeviceSpec{
		TDX_VERSION_1_0_DEVICE: {
			Version:    TDX_VERSION_1_0,
			DevicePath: TDX_VERSION_1_0_DEVICE,
			AllowedOperation: map[OperatorName]uintptr{
				GetTdReport: uintptr(binary.BigEndian.Uint32([]byte{192, 8, 'T', 1})),
				GetQuote:    uintptr(binary.BigEndian.Uint32([]byte{128, 8, 'T', 2})),
			},
		},
		TDX_VERSION_1_5_DEVICE: {
			Version:    TDX_VERSION_1_5,
			DevicePath: TDX_VERSION_1_5_DEVICE,
			AllowedOperation: map[OperatorName]uintptr{
				GetTdReport: uintptr(binary.BigEndian.Uint32([]byte{196, 64, 'T', 1})),
				GetQuote:    uintptr(binary.BigEndian.Uint32([]byte{128, 16, 'T', 4})),
			},
		},
	}
)
