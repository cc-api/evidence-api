package tdx

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"unsafe"

	"github.com/cc-api/cc-trusted-api/common/golang/cctrusted_base"
)

type QeCertDataType uint32

const (
	PCK_ID_PLAIN         QeCertDataType = 1
	PCK_ID_RSA_2048_OAEP QeCertDataType = 2
	PCK_ID_RSA_3072_OAEP QeCertDataType = 3
	PCK_LEAF_CERT_PLAIN  QeCertDataType = 4 // Currently not supported
	PCK_CERT_CHAIN       QeCertDataType = 5
	QE_REPORT_CERT       QeCertDataType = 6
	PLATFORM_MANIFEST    QeCertDataType = 7 // Currently not supported

	// QE Vendor ID. Unique identifier of the QE Vendor.
	// Note: Each vendor that decides to provide a customized Quote data
	// structure should have unique ID.
	//     e.g. Value: 939A7233F79C4CA9940A0DB3957F0607 (Intel® SGX QE Vendor)
	QE_VENDOR_INTEL_SGX = "939a7233f79c4ca9940a0db3957f0607"
)

func (t QeCertDataType) String() string {
	switch t {
	case PCK_ID_PLAIN:
		return " QeCertDataType.PCK_ID_PLAIN"
	case PCK_ID_RSA_2048_OAEP:
		return " QeCertDataType.PCK_ID_RSA_2048_OAEP"
	case PCK_ID_RSA_3072_OAEP:
		return " QeCertDataType.PCK_ID_RSA_3072_OAEP"
	case PCK_LEAF_CERT_PLAIN:
		return " QeCertDataType.PCK_LEAF_CERT_PLAIN"
	case PCK_CERT_CHAIN:
		return " QeCertDataType.PCK_CERT_CHAIN"
	case QE_REPORT_CERT:
		return " QeCertDataType.QE_REPORT_CERT"
	case PLATFORM_MANIFEST:
		return " QeCertDataType.PLATFORM_MANIFEST"
	}
	return ""
}

type TdxReportReq15 struct {
	ReportData [TD_REPORTDATA_LEN]uint8
	Tdreport   [TD_REPORT_LEN]uint8
}

type TdxQuoteReq struct {
	Buf uint64 // Pass user data that includes TDREPORT as input. Upon successful completion of IOCTL, output is copied back to the same buffer
	Len uint64 // Length of the Quote buffer
}

func NewTdxQuoteReqVer15(hdr *TdxQuoteHdr) *TdxQuoteReq {
	t := &TdxQuoteReq{}
	t.Buf = uint64(uintptr(unsafe.Pointer(hdr)))
	t.Len = TDX_QUOTE_LEN
	return t
}

type TdxQuoteHdr struct {
	Version        uint64               // Quote version, filled by TD
	Status         uint64               // Status code of Quote request, filled by VMM
	InLen          uint32               // Length of TDREPORT, filled by TD
	OutLen         uint32               // Length of Quote, filled by VMM
	DataLenBeBytes [4]uint8             // big-endian 4 bytes indicate the size of data following
	Data           [TDX_QUOTE_LEN]uint8 // Actual Quote data or TDREPORT on input
}

func NewTdxQuoteHdrVer15(req *QgsMsgGetQuoteReq) *TdxQuoteHdr {
	t := &TdxQuoteHdr{}
	reqBytes := req.Bytes()
	lenOfReqBytes := uint32(len(reqBytes))

	t.Version = 1
	t.Status = 0
	t.InLen = lenOfReqBytes + 4
	t.OutLen = 0

	be := make([]uint8, 4)
	binary.BigEndian.PutUint32(be, lenOfReqBytes)
	copy(t.DataLenBeBytes[:], be[0:4])

	copy(t.Data[:], reqBytes)
	return t
}

func NewTdxQuoteHdrFromBytes(b []byte) *TdxQuoteHdr {
	t := &TdxQuoteHdr{}
	t.Version = binary.LittleEndian.Uint64(b[0:8])
	t.Status = binary.LittleEndian.Uint64(b[8:16])
	t.InLen = binary.LittleEndian.Uint32(b[16:20])
	t.OutLen = binary.LittleEndian.Uint32(b[20:24])
	copy(t.DataLenBeBytes[:], b[24:28])
	copy(t.Data[:], b[28:28+TDX_QUOTE_LEN])

	return t
}

func (t *TdxQuoteHdr) LenOfBytes() uint32 {
	return 8*2 + 4*3 + TDX_QUOTE_LEN
}

type QgsMsgGetQuoteReq struct {
	Header     QgsMsgHeader
	ReportSize uint32 // cannot be 0
	IdListSize uint32 // length of id_list, in byte, can be 0
	// ReportIdList stores tdreport and id list.
	// TD_REPORT_LEN-fixed-lengthed tdreport in front of array,
	// and id list with the length IdListSize is stored in the tail.
	ReportIdList []uint8
}

func NewQgsMsgGetQuoteReqVer15(tdreport [TD_REPORT_LEN]uint8) *QgsMsgGetQuoteReq {
	q := &QgsMsgGetQuoteReq{}
	q.Header = *NewQgsMsgHeaderVer15()

	q.ReportSize = TD_REPORT_LEN
	q.IdListSize = 0
	q.ReportIdList = tdreport[:]
	// sizeof(Header) + sizeof(ReportSize) + sizeof(ReportIdList) + ReportSize + IdListSize
	q.Header.Size = q.Header.LenOfBytes() + 4 + 4 + q.ReportSize + q.IdListSize
	return q
}

func (q *QgsMsgGetQuoteReq) Bytes() []byte {
	headBytes := q.Header.Bytes()

	lenOfBytes := 4 + 4
	le := make([]uint8, lenOfBytes)
	binary.LittleEndian.PutUint32(le[0:4], q.ReportSize)
	binary.LittleEndian.PutUint32(le[4:8], q.IdListSize)

	le = append(le, q.ReportIdList...)

	return append(headBytes, le...)
}

type QgsMsgGetQuoteResp struct {
	Header         QgsMsgHeader         // header.type = GET_QUOTE_RESP
	SelectedIdSize uint32               // can be 0 in case only one id is sent in request
	QuoteSize      uint32               // length of quote_data, in byte
	IdQuote        [TDX_QUOTE_LEN]uint8 // selected id followed by quote
}

func NewQgsMsgGetQuoteRespFromBytes(b []byte) *QgsMsgGetQuoteResp {
	q := &QgsMsgGetQuoteResp{}
	lenOfHeader := q.Header.LenOfBytes()
	q.Header = *NewQgsMsgHeaderFromBytes(b[:lenOfHeader])
	q.SelectedIdSize = binary.LittleEndian.Uint32(b[lenOfHeader : lenOfHeader+4])
	q.QuoteSize = binary.LittleEndian.Uint32(b[lenOfHeader+4 : lenOfHeader+8])
	copy(q.IdQuote[:], b[lenOfHeader+8:])
	return q
}

type QgsMsgHeader struct {
	MajorVersion uint16     // TDX major version
	MinorVersion uint16     // TDX minor version
	MsgType      QgsMsgType // GET_QUOTE_REQ or GET_QUOTE_RESP
	Size         uint32     // size of the whole message, include this header, in byte
	ErrorCode    uint32     // used in response only
}

func NewQgsMsgHeaderVer15() *QgsMsgHeader {
	q := &QgsMsgHeader{}
	q.MajorVersion = 1
	q.MinorVersion = 0
	q.MsgType = GetQuoteReq
	q.Size = 0
	q.ErrorCode = 0
	return q
}

func NewQgsMsgHeaderFromBytes(b []byte) *QgsMsgHeader {
	q := &QgsMsgHeader{}
	q.MajorVersion = binary.LittleEndian.Uint16(b[0:2])
	q.MinorVersion = binary.LittleEndian.Uint16(b[2:4])

	q.MsgType = QgsMsgType(binary.LittleEndian.Uint32(b[4:8]))
	q.Size = binary.LittleEndian.Uint32(b[8:12])
	q.ErrorCode = binary.LittleEndian.Uint32(b[12:16])
	return q
}

func (q *QgsMsgHeader) Bytes() []byte {
	le := make([]uint8, q.LenOfBytes())

	binary.LittleEndian.PutUint16(le[0:2], q.MajorVersion)
	binary.LittleEndian.PutUint16(le[2:4], q.MinorVersion)

	binary.LittleEndian.PutUint32(le[4:8], uint32(q.MsgType))
	binary.LittleEndian.PutUint32(le[8:12], q.Size)
	binary.LittleEndian.PutUint32(le[12:16], q.ErrorCode)

	return le
}

func (q *QgsMsgHeader) LenOfBytes() uint32 {
	return 16
}

type TdxQuote struct {
	Header    *TdxQuoteHeader
	Body      *TdxQuoteBody
	Signature TdxQuoteSignature
}

func NewTdxQuote(b []byte) (*TdxQuote, error) {
	lenOfBytes := len(b)
	if lenOfBytes <= 0 {
		return nil, errors.New("the length of the raw quote can not less than 0s")
	}

	quote := &TdxQuote{}
	idx := 0

	if idx+48 > lenOfBytes {
		return nil, fmt.Errorf("tdx quote header need 48 bytes, but only provided %d", lenOfBytes-idx)
	}
	quote.Header = NewTdxQuoteHeader(b[idx : idx+48])
	idx += 48

	switch quote.Header.Version {
	case TDX_QUOTE_VERSION_4:
		if idx+584 > lenOfBytes {
			return nil, fmt.Errorf("tdx quote body need 584 bytes, but only provided %d", lenOfBytes-idx)
		}
		quote.Body = NewTdxQuoteBody(b[idx : idx+584])
		idx += 584

		if idx+4 > lenOfBytes {
			return nil, fmt.Errorf("the length of tdx quote signature parse need 4 bytes, but only provided %d", lenOfBytes-idx)
		}
		lenOfSig := binary.LittleEndian.Uint32(b[idx : idx+4])
		idx += 4

		if idx+int(lenOfSig) > lenOfBytes {
			return nil, fmt.Errorf("tdx quote signature need %d bytes, but only provided %d", lenOfSig, lenOfBytes-idx)
		}

		if quote.Header.AKType == AttestationKeyType_ECDSA_P256 {
			quote.Signature = NewTdxQuoteSignatureEcdsa256(b[idx : idx+int(lenOfSig)])
		} else {
			quote.Signature = NewTdxQuoteSignatureDefault(b[idx : idx+int(lenOfSig)])
		}
	case TDX_QUOTE_VERSION_5:
	}
	return quote, nil
}

func (q *TdxQuote) Dump(format cctrusted_base.QuoteDumpFormat, indent string) {
	l := log.Default()
	l.Printf("%s======================================\n", indent)
	l.Printf("%sTD Quote\n", indent)
	l.Printf("%s======================================\n", indent)
	q.Header.Dump(format, indent)
	q.Body.Dump(format, indent)
	q.Signature.Dump(format, indent)
}

type TdxQuoteHeader struct {
	raw       cctrusted_base.BinaryBlob
	Version   uint16
	AKType    AttestationKeyType
	TeeType   TeeType
	Reserved1 [2]byte
	Reserved2 [2]byte
	QeVendor  [16]byte
	UserData  [20]byte
}

func NewTdxQuoteHeader(b []byte) *TdxQuoteHeader {
	header := &TdxQuoteHeader{}
	header.raw = cctrusted_base.NewBinaryBlob(b, 0)
	blob := header.raw
	idx := 0

	header.Version, idx = blob.ParseUint16(idx)
	akType, idx := blob.ParseUint16(idx)
	header.AKType = AttestationKeyType(akType)
	teeType, idx := blob.ParseUint32(idx)
	header.TeeType = TeeType(teeType)

	r1, idx := blob.ParseBytes(idx, 2)
	copy(header.Reserved1[:], r1)
	r2, idx := blob.ParseBytes(idx, 2)
	copy(header.Reserved2[:], r2)

	vendor, idx := blob.ParseBytes(idx, 16)
	copy(header.QeVendor[:], vendor)

	userData, _ := blob.ParseBytes(idx, 20)
	copy(header.UserData[:], userData)
	return header
}

func (h *TdxQuoteHeader) Dump(format cctrusted_base.QuoteDumpFormat, indent string) {
	l := log.Default()
	l.Printf("%sTD Quote Header:\n", indent)
	indent += "  "
	if format == cctrusted_base.QuoteDumpFormatRaw {
		h.raw.Dump()
		return
	}

	l.Printf("%sHeader Version: %d\n", indent, h.Version)
	l.Printf("%sAttestation Key Type: %v\n", indent, h.AKType)
	l.Printf("%sTEE Type: %v\n", indent, h.TeeType)
	l.Printf("%sReserved 1: 0x%s\n", indent, hex.EncodeToString(h.Reserved1[:]))
	l.Printf("%sReserved 2: 0x%s\n", indent, hex.EncodeToString(h.Reserved2[:]))

	qeVendorHex := hex.EncodeToString(h.QeVendor[:])
	qeVendorName := ""
	if QE_VENDOR_INTEL_SGX == qeVendorHex {
		// This is the only defined QE Vendor so far according to the spec
		// The link to the spec is given in the docstring of TdxQuoteHeader.
		qeVendorName = " # Intel® SGX QE Vendor"
	}

	l.Printf("%sQE Vendor ID: 0x%s %s", indent, qeVendorHex, qeVendorName)
	l.Printf("%sUser Data: 0x%s", indent, hex.EncodeToString(h.UserData[:]))
}

type TdxQuoteBody struct {
	raw            cctrusted_base.BinaryBlob
	TeeTcbSvn      TdxQuoteTeeTcbSvn
	MrSeam         [48]byte
	MrSignerSeam   [48]byte
	SeamAttributes [8]byte
	TdAttributes   [8]byte
	Xfam           [8]byte
	MrTd           [48]byte
	MrConfigId     [48]byte
	MrOwner        [48]byte
	MrOwnerConfig  [48]byte
	Rtmr0          [48]byte
	Rtmr1          [48]byte
	Rtmr2          [48]byte
	Rtmr3          [48]byte
	ReportData     [64]byte
}

func NewTdxQuoteBody(b []byte) *TdxQuoteBody {
	body := &TdxQuoteBody{}
	body.raw = cctrusted_base.NewBinaryBlob(b, 0)
	idx := 0
	body.TeeTcbSvn = *NewTdxQuoteTeeTcbSvn(b[idx : idx+16])
	idx += 16
	copy(body.MrSeam[:], b[idx:idx+48])
	idx += 48
	copy(body.MrSignerSeam[:], b[idx:idx+48])
	idx += 48
	copy(body.SeamAttributes[:], b[idx:idx+8])
	idx += 8
	copy(body.TdAttributes[:], b[idx:idx+8])
	idx += 8
	copy(body.Xfam[:], b[idx:idx+8])
	idx += 8
	copy(body.MrTd[:], b[idx:idx+48])
	idx += 48
	copy(body.MrConfigId[:], b[idx:idx+48])
	idx += 48
	copy(body.MrOwner[:], b[idx:idx+48])
	idx += 48
	copy(body.MrOwnerConfig[:], b[idx:idx+48])
	idx += 48
	copy(body.Rtmr0[:], b[idx:idx+48])
	idx += 48
	copy(body.Rtmr1[:], b[idx:idx+48])
	idx += 48
	copy(body.Rtmr2[:], b[idx:idx+48])
	idx += 48
	copy(body.Rtmr3[:], b[idx:idx+48])
	idx += 48
	copy(body.ReportData[:], b[idx:idx+64])
	return body
}

func (b *TdxQuoteBody) Dump(format cctrusted_base.QuoteDumpFormat, indent string) {
	l := log.Default()
	l.Printf("%sTD Quote Body:\n", indent)
	indent += "  "

	if format == cctrusted_base.QuoteDumpFormatRaw {
		b.raw.Dump()
		return
	}

	b.TeeTcbSvn.Dump(format, indent)
	l.Printf("%sMRSEAM: 0x%s\n", indent, hex.EncodeToString(b.MrSeam[:]))
	l.Printf("%sMRSIGNERSEAM: 0x%s\n", indent, hex.EncodeToString(b.MrSignerSeam[:]))
	l.Printf("%sSEAMATTRIBUTES: 0x%s\n", indent, hex.EncodeToString(b.SeamAttributes[:]))
	l.Printf("%sTDATTRIBUTES: 0x%s\n", indent, hex.EncodeToString(b.TdAttributes[:]))
	l.Printf("%sXFAM: 0x%s\n", indent, hex.EncodeToString(b.Xfam[:]))
	l.Printf("%sMRTD: 0x%s\n", indent, hex.EncodeToString(b.MrTd[:]))
	l.Printf("%sMRCONFIG: 0x%s\n", indent, hex.EncodeToString(b.MrConfigId[:]))
	l.Printf("%sMROWNER: 0x%s\n", indent, hex.EncodeToString(b.MrOwner[:]))
	l.Printf("%sMROWNERCONFIG: 0x%s\n", indent, hex.EncodeToString(b.MrOwnerConfig[:]))
	l.Printf("%sRTMR0: 0x%s\n", indent, hex.EncodeToString(b.Rtmr0[:]))
	l.Printf("%sRTMR1: 0x%s\n", indent, hex.EncodeToString(b.Rtmr1[:]))
	l.Printf("%sRTMR2: 0x%s\n", indent, hex.EncodeToString(b.Rtmr2[:]))
	l.Printf("%sRTMR3: 0x%s\n", indent, hex.EncodeToString(b.Rtmr3[:]))
	l.Printf("%sREPORTDATA: 0x%s\n", indent, hex.EncodeToString(b.ReportData[:]))
}

type TdxQuoteTeeTcbSvn struct {
	raw cctrusted_base.BinaryBlob
}

func NewTdxQuoteTeeTcbSvn(b []byte) *TdxQuoteTeeTcbSvn {
	return &TdxQuoteTeeTcbSvn{
		raw: cctrusted_base.NewBinaryBlob(b, 0),
	}
}

func (s *TdxQuoteTeeTcbSvn) Dump(format cctrusted_base.QuoteDumpFormat, indent string) {
	l := log.Default()
	l.Printf("%sTdxQuoteTeeTcbSvn:\n", indent)
	indent += "  "
	if format == cctrusted_base.QuoteDumpFormatRaw {
		s.raw.Dump()
		return
	}

	l.Printf("%stdxtcbcomp01: %d\n", indent, s.raw.Binary[0])
	l.Printf("%stdxtcbcomp02: %d\n", indent, s.raw.Binary[1])
	l.Printf("%stdxtcbcomp03: %d\n", indent, s.raw.Binary[2])
	l.Printf("%stdxtcbcomp04: %d\n", indent, s.raw.Binary[3])
	l.Printf("%stdxtcbcomp05: %d\n", indent, s.raw.Binary[4])
	l.Printf("%stdxtcbcomp06: %d\n", indent, s.raw.Binary[5])
	l.Printf("%stdxtcbcomp07: %d\n", indent, s.raw.Binary[6])
	l.Printf("%stdxtcbcomp08: %d\n", indent, s.raw.Binary[7])
	l.Printf("%stdxtcbcomp09: %d\n", indent, s.raw.Binary[8])
	l.Printf("%stdxtcbcomp10: %d\n", indent, s.raw.Binary[9])
	l.Printf("%stdxtcbcomp11: %d\n", indent, s.raw.Binary[10])
	l.Printf("%stdxtcbcomp12: %d\n", indent, s.raw.Binary[11])
	l.Printf("%stdxtcbcomp13: %d\n", indent, s.raw.Binary[12])
	l.Printf("%stdxtcbcomp14: %d\n", indent, s.raw.Binary[13])
	l.Printf("%stdxtcbcomp15: %d\n", indent, s.raw.Binary[14])
	l.Printf("%stdxtcbcomp16: %d\n", indent, s.raw.Binary[15])

}

type TdxQuoteSignature interface {
	Dump(cctrusted_base.QuoteDumpFormat, string)
}

var _ TdxQuoteSignature = (*TdxQuoteSignatureDefault)(nil)

type TdxQuoteSignatureDefault struct {
}

// Dump implements TdxQuoteSignature.
func (*TdxQuoteSignatureDefault) Dump(cctrusted_base.QuoteDumpFormat, string) {
	panic("unimplemented")
}

func NewTdxQuoteSignatureDefault(b []byte) *TdxQuoteSignatureDefault {
	sig := &TdxQuoteSignatureDefault{}
	return sig
}

var _ TdxQuoteSignature = (*TdxQuoteSignatureEcdsa256)(nil)

type TdxQuoteSignatureEcdsa256 struct {
	raw    cctrusted_base.BinaryBlob
	Sig    [64]byte
	Ak     [64]byte
	QeCert TdxQuoteQeCert
}

func NewTdxQuoteSignatureEcdsa256(b []byte) *TdxQuoteSignatureEcdsa256 {
	sig := &TdxQuoteSignatureEcdsa256{}
	sig.raw = cctrusted_base.NewBinaryBlob(b, 0)
	copy(sig.Sig[:], b[0:64])
	copy(sig.Ak[:], b[64:128])
	sig.QeCert = *NewTdxQuoteQeCert(b[128:])
	return sig
}

// Dump implements TdxQuoteSignature.
func (s *TdxQuoteSignatureEcdsa256) Dump(format cctrusted_base.QuoteDumpFormat, indent string) {
	l := log.Default()
	l.Printf("%sTD Quote Signature:\n", indent)
	indent += "  "
	if format == cctrusted_base.QuoteDumpFormatRaw {
		s.raw.Dump()
		return
	}

	l.Printf("  Quote Signature (ECDSA P-256 Signature): 0x%s\n", hex.EncodeToString(s.Sig[:]))
	l.Printf("  ECDSA Attestation Key (ECDSA P-256 Public Key): 0x%s\n", hex.EncodeToString(s.Ak[:]))
	s.QeCert.Dump(format, indent)
}

type TdxQuoteQeCert struct {
	raw        cctrusted_base.BinaryBlob
	CertType   QeCertDataType
	ReportCert *TdxQuoteQeReportCert
	CertData   []byte
}

func NewTdxQuoteQeCert(b []byte) *TdxQuoteQeCert {
	cert := &TdxQuoteQeCert{}
	cert.raw = cctrusted_base.NewBinaryBlob(b, 0)
	certType, idx := cert.raw.ParseUint16(0)
	cert.CertType = QeCertDataType(certType)
	certSize, idx := cert.raw.ParseUint32(idx)
	if cert.CertType == QE_REPORT_CERT {
		cert.ReportCert = NewTdxQuoteQeReportCert(b[idx : idx+int(certSize)])
	} else {
		cert.CertData = b[idx : idx+int(certSize)]
	}
	return cert
}

func (c *TdxQuoteQeCert) Dump(format cctrusted_base.QuoteDumpFormat, indent string) {
	l := log.Default()
	l.Printf("%sTdxQuoteQeCert:\n", indent)
	indent += "  "
	if format == cctrusted_base.QuoteDumpFormatRaw {
		c.raw.Dump()
		return
	}

	l.Printf("%sQuote QE Cert Data Type: %v", indent, c.CertType)
	switch c.CertType {
	case QE_REPORT_CERT:
		c.ReportCert.Dump(format, indent)
	case PCK_CERT_CHAIN:
		l.Printf("%sPCK Cert Chain (PEM, Leaf||Intermediate||Root):\n", indent)
		l.Printf("%s%s\n", indent, string(c.CertData))
	default:
		l.Printf("%sQuote QE Cert Data: %s\n", indent, c.CertData)
	}

}

type TdxQuoteQeReportCert struct {
	raw         cctrusted_base.BinaryBlob
	QeReport    TdxEnclaveReportBody
	QeReportSig [64]byte
	QeAuthData  []byte
	QeCertData  *TdxQuoteQeCert
}

func NewTdxQuoteQeReportCert(b []byte) *TdxQuoteQeReportCert {
	c := &TdxQuoteQeReportCert{}
	c.raw = cctrusted_base.NewBinaryBlob(b, 0)
	c.QeReport = *NewTdxEnclaveReportBody(b[0:384])
	copy(c.QeReportSig[:], b[384:448])
	authDataSize, idx := c.raw.ParseUint16(448)
	c.QeAuthData = b[idx : idx+int(authDataSize)]
	c.QeCertData = NewTdxQuoteQeCert(b[idx+int(authDataSize):])
	return c
}

func (c *TdxQuoteQeReportCert) Dump(format cctrusted_base.QuoteDumpFormat, indent string) {
	l := log.Default()
	l.Printf("%sTdxQuoteQeReportCert:\n", indent)
	indent += "  "
	if format == cctrusted_base.QuoteDumpFormatRaw {
		c.raw.Dump()
		return
	}

	c.QeReport.Dump(format, indent)
	l.Printf("  Quote QE Report Signature: 0x%s\n", hex.EncodeToString(c.QeReportSig[:]))
	if len(c.QeAuthData) != 0 {
		l.Printf("  Quote QE Authentication Data: 0x%s\n", hex.EncodeToString(c.QeAuthData))
	} else {
		l.Println("  Quote QE Authentication Data: None")
	}
	c.QeCertData.Dump(format, indent)
}

type TdxEnclaveReportBody struct {
	raw        cctrusted_base.BinaryBlob
	CpuSvn     [16]byte
	Miscselect uint32
	Reserved1  [28]byte
	Attributes [16]byte
	Mrenclave  [32]byte
	Reserved2  [32]byte
	MrSigner   [32]byte
	Reserved3  [96]byte
	IsvProdid  uint16
	IsvSvn     uint16
	Reserved4  [60]byte
	ReportData [64]byte
}

func NewTdxEnclaveReportBody(b []byte) *TdxEnclaveReportBody {
	body := &TdxEnclaveReportBody{}
	body.raw = cctrusted_base.NewBinaryBlob(b, 0)
	copy(body.CpuSvn[:], b[0:16])
	body.Miscselect, _ = body.raw.ParseUint32(16)
	copy(body.Reserved1[:], b[20:48])
	copy(body.Attributes[:], b[48:64])
	copy(body.Mrenclave[:], b[64:96])
	copy(body.Reserved2[:], b[96:128])
	copy(body.MrSigner[:], b[128:160])
	copy(body.Reserved3[:], b[160:256])
	body.IsvProdid, _ = body.raw.ParseUint16(256)
	body.IsvSvn, _ = body.raw.ParseUint16(258)
	copy(body.Reserved4[:], b[260:320])
	copy(body.ReportData[:], b[320:384])
	return body
}

func (b *TdxEnclaveReportBody) Dump(format cctrusted_base.QuoteDumpFormat, indent string) {
	l := log.Default()
	l.Printf("%sTdxEnclaveReportBody:\n", indent)
	indent += "  "
	if format == cctrusted_base.QuoteDumpFormatRaw {
		b.raw.Dump()
		return
	}

	l.Printf("%sCPU SVN: 0x%s\n", indent, hex.EncodeToString(b.CpuSvn[:]))
	l.Printf("%sMISCSELECT: %d\n", indent, b.Miscselect)
	l.Printf("%sReserved: 0x%s\n", indent, hex.EncodeToString(b.Reserved1[:]))
	l.Printf("%sAttributes: 0x%s\n", indent, hex.EncodeToString(b.Attributes[:]))
	l.Printf("%sMRENCLAVE:0x%s\n", indent, hex.EncodeToString(b.Mrenclave[:]))
	l.Printf("%sReserved: 0x%s\n", indent, hex.EncodeToString(b.Reserved2[:]))
	l.Printf("%sMRSIGNER: 0x%s\n", indent, hex.EncodeToString(b.MrSigner[:]))
	l.Printf("%sReserved: 0x%s\n", indent, hex.EncodeToString(b.Reserved3[:]))
	l.Printf("%sISV ProdID: %d\n", indent, b.IsvProdid)
	l.Printf("%sISV SVN: %d\n", indent, b.IsvSvn)
	l.Printf("%sReserved: 0x%s\n", indent, hex.EncodeToString(b.Reserved4[:]))
	l.Printf("%sReport Data: 0x%s\n", indent, hex.EncodeToString(b.ReportData[:]))
}
