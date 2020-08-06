// SPDX-License-Identifier: Apache-2.0
// Copyright © 2019 Intel Corporation

package pb

import (
	context "context"
	fmt "fmt"
	math "math"

	proto "github.com/golang/protobuf/proto"
	empty "github.com/golang/protobuf/ptypes/empty"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

// DNS Resource Record (https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4)
type RType int32

const (
	RType_None       RType = 0
	RType_A          RType = 1
	RType_NS         RType = 2
	RType_MD         RType = 3
	RType_MF         RType = 4
	RType_CNAME      RType = 5
	RType_SOA        RType = 6
	RType_MB         RType = 7
	RType_MG         RType = 8
	RType_MR         RType = 9
	RType_NULL       RType = 10
	RType_PTR        RType = 12
	RType_HINFO      RType = 13
	RType_MINFO      RType = 14
	RType_MX         RType = 15
	RType_TXT        RType = 16
	RType_RP         RType = 17
	RType_AFSDB      RType = 18
	RType_X25        RType = 19
	RType_ISDN       RType = 20
	RType_RT         RType = 21
	RType_NSAPPTR    RType = 23
	RType_SIG        RType = 24
	RType_KEY        RType = 25
	RType_PX         RType = 26
	RType_GPOS       RType = 27
	RType_AAAA       RType = 28
	RType_LOC        RType = 29
	RType_NXT        RType = 30
	RType_EID        RType = 31
	RType_NIMLOC     RType = 32
	RType_SRV        RType = 33
	RType_ATMA       RType = 34
	RType_NAPTR      RType = 35
	RType_KX         RType = 36
	RType_CERT       RType = 37
	RType_DNAME      RType = 39
	RType_OPT        RType = 41
	RType_DS         RType = 43
	RType_SSHFP      RType = 44
	RType_RRSIG      RType = 46
	RType_NSEC       RType = 47
	RType_DNSKEY     RType = 48
	RType_DHCID      RType = 49
	RType_NSEC3      RType = 50
	RType_NSEC3PARAM RType = 51
	RType_TLSA       RType = 52
	RType_SMIMEA     RType = 53
	RType_HIP        RType = 55
	RType_NINFO      RType = 56
	RType_RKEY       RType = 57
	RType_TALINK     RType = 58
	RType_CDS        RType = 59
	RType_CDNSKEY    RType = 60
	RType_OPENPGPKEY RType = 61
	RType_SPF        RType = 99
	RType_UINFO      RType = 100
	RType_UID        RType = 101
	RType_GID        RType = 102
	RType_UNSPEC     RType = 103
	RType_NID        RType = 104
	RType_L32        RType = 105
	RType_L64        RType = 106
	RType_LP         RType = 107
	RType_EUI48      RType = 108
	RType_EUI64      RType = 109
	RType_URI        RType = 256
	RType_CAA        RType = 257
	RType_AVC        RType = 258
	RType_TKEY       RType = 249
	RType_TSIG       RType = 250
	// valid Question.Q only
	RType_IXFR     RType = 251
	RType_AXFR     RType = 252
	RType_MAILB    RType = 253
	RType_MAILA    RType = 254
	RType_ANY      RType = 255
	RType_TA       RType = 32768
	RType_DLV      RType = 32769
	RType_Reserved RType = 65535
)

var RType_name = map[int32]string{
	0:     "None",
	1:     "A",
	2:     "NS",
	3:     "MD",
	4:     "MF",
	5:     "CNAME",
	6:     "SOA",
	7:     "MB",
	8:     "MG",
	9:     "MR",
	10:    "NULL",
	12:    "PTR",
	13:    "HINFO",
	14:    "MINFO",
	15:    "MX",
	16:    "TXT",
	17:    "RP",
	18:    "AFSDB",
	19:    "X25",
	20:    "ISDN",
	21:    "RT",
	23:    "NSAPPTR",
	24:    "SIG",
	25:    "KEY",
	26:    "PX",
	27:    "GPOS",
	28:    "AAAA",
	29:    "LOC",
	30:    "NXT",
	31:    "EID",
	32:    "NIMLOC",
	33:    "SRV",
	34:    "ATMA",
	35:    "NAPTR",
	36:    "KX",
	37:    "CERT",
	39:    "DNAME",
	41:    "OPT",
	43:    "DS",
	44:    "SSHFP",
	46:    "RRSIG",
	47:    "NSEC",
	48:    "DNSKEY",
	49:    "DHCID",
	50:    "NSEC3",
	51:    "NSEC3PARAM",
	52:    "TLSA",
	53:    "SMIMEA",
	55:    "HIP",
	56:    "NINFO",
	57:    "RKEY",
	58:    "TALINK",
	59:    "CDS",
	60:    "CDNSKEY",
	61:    "OPENPGPKEY",
	99:    "SPF",
	100:   "UINFO",
	101:   "UID",
	102:   "GID",
	103:   "UNSPEC",
	104:   "NID",
	105:   "L32",
	106:   "L64",
	107:   "LP",
	108:   "EUI48",
	109:   "EUI64",
	256:   "URI",
	257:   "CAA",
	258:   "AVC",
	249:   "TKEY",
	250:   "TSIG",
	251:   "IXFR",
	252:   "AXFR",
	253:   "MAILB",
	254:   "MAILA",
	255:   "ANY",
	32768: "TA",
	32769: "DLV",
	65535: "Reserved",
}

var RType_value = map[string]int32{
	"None":       0,
	"A":          1,
	"NS":         2,
	"MD":         3,
	"MF":         4,
	"CNAME":      5,
	"SOA":        6,
	"MB":         7,
	"MG":         8,
	"MR":         9,
	"NULL":       10,
	"PTR":        12,
	"HINFO":      13,
	"MINFO":      14,
	"MX":         15,
	"TXT":        16,
	"RP":         17,
	"AFSDB":      18,
	"X25":        19,
	"ISDN":       20,
	"RT":         21,
	"NSAPPTR":    23,
	"SIG":        24,
	"KEY":        25,
	"PX":         26,
	"GPOS":       27,
	"AAAA":       28,
	"LOC":        29,
	"NXT":        30,
	"EID":        31,
	"NIMLOC":     32,
	"SRV":        33,
	"ATMA":       34,
	"NAPTR":      35,
	"KX":         36,
	"CERT":       37,
	"DNAME":      39,
	"OPT":        41,
	"DS":         43,
	"SSHFP":      44,
	"RRSIG":      46,
	"NSEC":       47,
	"DNSKEY":     48,
	"DHCID":      49,
	"NSEC3":      50,
	"NSEC3PARAM": 51,
	"TLSA":       52,
	"SMIMEA":     53,
	"HIP":        55,
	"NINFO":      56,
	"RKEY":       57,
	"TALINK":     58,
	"CDS":        59,
	"CDNSKEY":    60,
	"OPENPGPKEY": 61,
	"SPF":        99,
	"UINFO":      100,
	"UID":        101,
	"GID":        102,
	"UNSPEC":     103,
	"NID":        104,
	"L32":        105,
	"L64":        106,
	"LP":         107,
	"EUI48":      108,
	"EUI64":      109,
	"URI":        256,
	"CAA":        257,
	"AVC":        258,
	"TKEY":       249,
	"TSIG":       250,
	"IXFR":       251,
	"AXFR":       252,
	"MAILB":      253,
	"MAILA":      254,
	"ANY":        255,
	"TA":         32768,
	"DLV":        32769,
	"Reserved":   65535,
}

func (x RType) String() string {
	return proto.EnumName(RType_name, int32(x))
}

func (RType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_f5838971722c666f, []int{0}
}

type HostRecordSet struct {
	RecordType           RType    `protobuf:"varint,1,opt,name=record_type,json=recordType,proto3,enum=pb.RType" json:"record_type,omitempty"`
	Fqdn                 string   `protobuf:"bytes,2,opt,name=fqdn,proto3" json:"fqdn,omitempty"`
	Addresses            [][]byte `protobuf:"bytes,3,rep,name=addresses,proto3" json:"addresses,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *HostRecordSet) Reset()         { *m = HostRecordSet{} }
func (m *HostRecordSet) String() string { return proto.CompactTextString(m) }
func (*HostRecordSet) ProtoMessage()    {}
func (*HostRecordSet) Descriptor() ([]byte, []int) {
	return fileDescriptor_f5838971722c666f, []int{0}
}

func (m *HostRecordSet) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_HostRecordSet.Unmarshal(m, b)
}
func (m *HostRecordSet) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_HostRecordSet.Marshal(b, m, deterministic)
}
func (m *HostRecordSet) XXX_Merge(src proto.Message) {
	xxx_messageInfo_HostRecordSet.Merge(m, src)
}
func (m *HostRecordSet) XXX_Size() int {
	return xxx_messageInfo_HostRecordSet.Size(m)
}
func (m *HostRecordSet) XXX_DiscardUnknown() {
	xxx_messageInfo_HostRecordSet.DiscardUnknown(m)
}

var xxx_messageInfo_HostRecordSet proto.InternalMessageInfo

func (m *HostRecordSet) GetRecordType() RType {
	if m != nil {
		return m.RecordType
	}
	return RType_None
}

func (m *HostRecordSet) GetFqdn() string {
	if m != nil {
		return m.Fqdn
	}
	return ""
}

func (m *HostRecordSet) GetAddresses() [][]byte {
	if m != nil {
		return m.Addresses
	}
	return nil
}

// RecordSet represents all values associated with an FQDN and type
//
// Example: An A record for foo.example.org may have one or more addresses,
// and the corresponding RecordSet includes all addresses.
type RecordSet struct {
	RecordType           RType    `protobuf:"varint,1,opt,name=record_type,json=recordType,proto3,enum=pb.RType" json:"record_type,omitempty"`
	Fqdn                 string   `protobuf:"bytes,2,opt,name=fqdn,proto3" json:"fqdn,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *RecordSet) Reset()         { *m = RecordSet{} }
func (m *RecordSet) String() string { return proto.CompactTextString(m) }
func (*RecordSet) ProtoMessage()    {}
func (*RecordSet) Descriptor() ([]byte, []int) {
	return fileDescriptor_f5838971722c666f, []int{1}
}

func (m *RecordSet) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_RecordSet.Unmarshal(m, b)
}
func (m *RecordSet) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_RecordSet.Marshal(b, m, deterministic)
}
func (m *RecordSet) XXX_Merge(src proto.Message) {
	xxx_messageInfo_RecordSet.Merge(m, src)
}
func (m *RecordSet) XXX_Size() int {
	return xxx_messageInfo_RecordSet.Size(m)
}
func (m *RecordSet) XXX_DiscardUnknown() {
	xxx_messageInfo_RecordSet.DiscardUnknown(m)
}

var xxx_messageInfo_RecordSet proto.InternalMessageInfo

func (m *RecordSet) GetRecordType() RType {
	if m != nil {
		return m.RecordType
	}
	return RType_None
}

func (m *RecordSet) GetFqdn() string {
	if m != nil {
		return m.Fqdn
	}
	return ""
}

func init() {
	proto.RegisterEnum("pb.RType", RType_name, RType_value)
	proto.RegisterType((*HostRecordSet)(nil), "pb.HostRecordSet")
	proto.RegisterType((*RecordSet)(nil), "pb.RecordSet")
}

func init() { proto.RegisterFile("resolver.proto", fileDescriptor_f5838971722c666f) }

var fileDescriptor_f5838971722c666f = []byte{
	// 742 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xac, 0x94, 0x6f, 0x73, 0xdb, 0x44,
	0x10, 0xc6, 0x2b, 0x39, 0x76, 0xe2, 0x6b, 0x63, 0x9e, 0x5e, 0x0b, 0x84, 0xb4, 0x40, 0x08, 0x30,
	0x84, 0xc2, 0x38, 0xe0, 0xa4, 0xa5, 0xfc, 0x9d, 0xb9, 0x48, 0xb2, 0x7d, 0x63, 0x49, 0xd6, 0xdc,
	0xc9, 0x19, 0xf7, 0x15, 0x53, 0xd7, 0x97, 0x34, 0xe0, 0x44, 0x46, 0x56, 0x33, 0x93, 0x77, 0x2e,
	0x1f, 0x80, 0x8f, 0xc1, 0x77, 0xe4, 0x6f, 0x98, 0xdd, 0x14, 0x98, 0xbe, 0xe2, 0x0d, 0xaf, 0xee,
	0xa7, 0xdd, 0x67, 0x9f, 0xdd, 0xd9, 0x19, 0xad, 0x68, 0x95, 0x6e, 0x51, 0xcc, 0xce, 0x5d, 0xd9,
	0x9e, 0x97, 0x45, 0x55, 0x48, 0x7f, 0x3e, 0xd9, 0xbc, 0x73, 0x5c, 0x14, 0xc7, 0x33, 0xb7, 0xcb,
	0x91, 0xc9, 0xb3, 0xa3, 0x5d, 0x77, 0x3a, 0xaf, 0x2e, 0xae, 0x04, 0xdb, 0xa7, 0x62, 0xbd, 0x5f,
	0x2c, 0x2a, 0xe3, 0x9e, 0x14, 0xe5, 0xd4, 0xba, 0x4a, 0xde, 0x13, 0xd7, 0x4b, 0xfe, 0xf8, 0xb6,
	0xba, 0x98, 0xbb, 0x0d, 0x6f, 0xcb, 0xdb, 0x69, 0x75, 0x9a, 0xed, 0xf9, 0xa4, 0x6d, 0xf2, 0x8b,
	0xb9, 0x33, 0xe2, 0x2a, 0x4b, 0x2c, 0xa5, 0x58, 0x39, 0xfa, 0x61, 0x7a, 0xb6, 0xe1, 0x6f, 0x79,
	0x3b, 0x4d, 0xc3, 0x2c, 0xef, 0x8a, 0xe6, 0xe3, 0xe9, 0xb4, 0x74, 0x8b, 0x85, 0x5b, 0x6c, 0xd4,
	0xb6, 0x6a, 0x3b, 0x37, 0xcc, 0xbf, 0x81, 0xed, 0x81, 0x68, 0xfe, 0x6f, 0xad, 0xee, 0xfd, 0xdc,
	0x10, 0x75, 0x56, 0xca, 0x35, 0xb1, 0x92, 0x16, 0x67, 0x0e, 0xd7, 0x64, 0x5d, 0x78, 0x0a, 0x9e,
	0x6c, 0x08, 0x3f, 0xb5, 0xf0, 0xe9, 0x4d, 0x42, 0xd4, 0xf8, 0xed, 0x62, 0x45, 0x36, 0x45, 0x3d,
	0x48, 0x55, 0x12, 0xa1, 0x2e, 0x57, 0x45, 0xcd, 0x0e, 0x15, 0x1a, 0x9c, 0x3b, 0xc0, 0x2a, 0xbf,
	0x3d, 0xac, 0xf1, 0x6b, 0xd0, 0x64, 0xd3, 0x51, 0x1c, 0x43, 0x90, 0x34, 0xcb, 0x0d, 0x6e, 0x50,
	0x79, 0x5f, 0xa7, 0xdd, 0x21, 0xd6, 0x09, 0x13, 0xc6, 0x16, 0x17, 0x8c, 0xf1, 0x0a, 0xc9, 0xf2,
	0x71, 0x0e, 0x50, 0xc0, 0x64, 0xb8, 0x49, 0x1a, 0xd5, 0xb5, 0xe1, 0x01, 0x24, 0xe5, 0xc6, 0x9d,
	0xfb, 0xb8, 0x45, 0xae, 0xda, 0x86, 0x29, 0x6e, 0xb3, 0x2a, 0xc7, 0xab, 0xf2, 0xba, 0x58, 0x4d,
	0xad, 0xca, 0xa8, 0xc3, 0xeb, 0x3c, 0x95, 0xee, 0x61, 0x83, 0x60, 0x10, 0x3d, 0xc2, 0x1b, 0x24,
	0xcb, 0xc6, 0xd8, 0xa4, 0xc2, 0x5e, 0x36, 0xb4, 0xb8, 0x43, 0xa4, 0x94, 0x52, 0xb8, 0x4b, 0xa2,
	0x78, 0x18, 0xe0, 0x4d, 0x82, 0x74, 0x9c, 0xe3, 0x2d, 0x82, 0x48, 0x87, 0x78, 0x5b, 0x0a, 0xd1,
	0x48, 0x75, 0x42, 0xd9, 0x2d, 0x36, 0x35, 0x87, 0x78, 0x87, 0x2b, 0xf3, 0x44, 0x61, 0x9b, 0x46,
	0x4b, 0x15, 0xb5, 0x7c, 0x97, 0x1a, 0x0c, 0xc6, 0x78, 0x8f, 0x92, 0x41, 0x64, 0x72, 0xbc, 0x4f,
	0xc9, 0x90, 0xb7, 0xf4, 0x01, 0x95, 0x0e, 0xb3, 0x1c, 0x1f, 0x92, 0x2a, 0xb4, 0xf8, 0x88, 0x72,
	0xd6, 0xf6, 0xbb, 0x19, 0x3e, 0x26, 0x34, 0x86, 0xa6, 0x6d, 0xf3, 0xae, 0x6c, 0x14, 0x60, 0x97,
	0xfa, 0x86, 0xa9, 0xa5, 0xd1, 0x3f, 0x61, 0x9f, 0x7e, 0xa0, 0x43, 0x7c, 0xca, 0xfd, 0x6c, 0x14,
	0xec, 0xa1, 0x23, 0x5b, 0x42, 0x30, 0x66, 0xca, 0xa8, 0x04, 0x7b, 0x54, 0x9b, 0xc7, 0x56, 0x61,
	0x9f, 0x6a, 0x6d, 0xa2, 0x93, 0x48, 0xe1, 0x3e, 0x35, 0xee, 0xeb, 0x0c, 0x9f, 0x71, 0x25, 0x2f,
	0xfa, 0x21, 0x29, 0x0d, 0x39, 0x7f, 0x4e, 0xca, 0x5c, 0xc5, 0x3a, 0x1d, 0xe0, 0x0b, 0x52, 0x06,
	0xa1, 0xc5, 0x97, 0xb4, 0xc8, 0xe0, 0x45, 0xef, 0xaf, 0xa8, 0xcb, 0x30, 0x8b, 0xd2, 0xac, 0x97,
	0xd1, 0xf7, 0xd7, 0xbc, 0x83, 0xac, 0x8b, 0x27, 0xe4, 0x37, 0x62, 0xbf, 0x29, 0xc5, 0x46, 0x3a,
	0x84, 0x23, 0xe8, 0xe9, 0x10, 0x47, 0xe4, 0x3b, 0x4a, 0x6d, 0x16, 0x05, 0x38, 0xe6, 0x9d, 0xea,
	0x10, 0x4f, 0x79, 0xcb, 0x7b, 0x1d, 0x9c, 0x30, 0x3c, 0xd8, 0xc7, 0x77, 0xb4, 0x8c, 0x38, 0xc3,
	0xf7, 0xe4, 0x15, 0x8d, 0xf4, 0xfe, 0x43, 0xcc, 0x5e, 0xe0, 0x83, 0x7d, 0x9c, 0xca, 0x35, 0x51,
	0x1b, 0x19, 0x8d, 0xa5, 0x4f, 0x14, 0x28, 0x85, 0xe7, 0x4c, 0xea, 0x30, 0xc0, 0x8f, 0xbe, 0x6c,
	0x8a, 0x95, 0x9c, 0x46, 0xfa, 0xc5, 0x63, 0xa4, 0xfd, 0xfd, 0xca, 0xa8, 0xc7, 0x5d, 0x83, 0xdf,
	0x18, 0x15, 0xe1, 0xef, 0x9e, 0x14, 0xa2, 0x9e, 0x28, 0x1d, 0x1f, 0xe0, 0x8f, 0x7f, 0x58, 0xe1,
	0x4f, 0x8f, 0xdd, 0xd2, 0x47, 0xb8, 0x24, 0xf2, 0x73, 0x85, 0xe5, 0x92, 0x7c, 0x6b, 0x61, 0x7c,
	0x88, 0xe7, 0x4b, 0x5f, 0xb6, 0xc4, 0x9a, 0x71, 0x0b, 0x57, 0x9e, 0xbb, 0x29, 0x2e, 0x2f, 0x6b,
	0x9d, 0x9f, 0x3c, 0xb1, 0x1a, 0x14, 0x67, 0x55, 0x59, 0xcc, 0x64, 0x20, 0x6e, 0x5b, 0x57, 0xa9,
	0x67, 0xd5, 0xd3, 0xa2, 0x3c, 0xa9, 0x1e, 0x57, 0x27, 0xe7, 0x8e, 0x0e, 0x80, 0xbc, 0x49, 0xff,
	0xdd, 0x4b, 0xa7, 0x60, 0xf3, 0xb5, 0xf6, 0xd5, 0xe5, 0x68, 0xff, 0x7d, 0x39, 0xda, 0x11, 0x5d,
	0x8e, 0xed, 0x6b, 0xf2, 0x1b, 0x71, 0x2b, 0x74, 0x33, 0x57, 0xb9, 0x97, 0x7c, 0xe4, 0x3a, 0xff,
	0xbb, 0xff, 0x5d, 0x3f, 0x69, 0x70, 0x64, 0xef, 0xaf, 0x00, 0x00, 0x00, 0xff, 0xff, 0x28, 0x5a,
	0x56, 0x27, 0xaf, 0x04, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// ControlClient is the client API for Control service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type ControlClient interface {
	SetAuthoritativeHost(ctx context.Context, in *HostRecordSet, opts ...grpc.CallOption) (*empty.Empty, error)
	DeleteAuthoritative(ctx context.Context, in *RecordSet, opts ...grpc.CallOption) (*empty.Empty, error)
}

type controlClient struct {
	cc *grpc.ClientConn
}

func NewControlClient(cc *grpc.ClientConn) ControlClient {
	return &controlClient{cc}
}

func (c *controlClient) SetAuthoritativeHost(ctx context.Context, in *HostRecordSet, opts ...grpc.CallOption) (*empty.Empty, error) {
	out := new(empty.Empty)
	err := c.cc.Invoke(ctx, "/pb.Control/SetAuthoritativeHost", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *controlClient) DeleteAuthoritative(ctx context.Context, in *RecordSet, opts ...grpc.CallOption) (*empty.Empty, error) {
	out := new(empty.Empty)
	err := c.cc.Invoke(ctx, "/pb.Control/DeleteAuthoritative", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ControlServer is the server API for Control service.
type ControlServer interface {
	SetAuthoritativeHost(context.Context, *HostRecordSet) (*empty.Empty, error)
	DeleteAuthoritative(context.Context, *RecordSet) (*empty.Empty, error)
}

func RegisterControlServer(s *grpc.Server, srv ControlServer) {
	s.RegisterService(&_Control_serviceDesc, srv)
}

func _Control_SetAuthoritativeHost_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(HostRecordSet)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ControlServer).SetAuthoritativeHost(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/pb.Control/SetAuthoritativeHost",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ControlServer).SetAuthoritativeHost(ctx, req.(*HostRecordSet))
	}
	return interceptor(ctx, in, info, handler)
}

func _Control_DeleteAuthoritative_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RecordSet)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ControlServer).DeleteAuthoritative(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/pb.Control/DeleteAuthoritative",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ControlServer).DeleteAuthoritative(ctx, req.(*RecordSet))
	}
	return interceptor(ctx, in, info, handler)
}

var _Control_serviceDesc = grpc.ServiceDesc{
	ServiceName: "pb.Control",
	HandlerType: (*ControlServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "SetAuthoritativeHost",
			Handler:    _Control_SetAuthoritativeHost_Handler,
		},
		{
			MethodName: "DeleteAuthoritative",
			Handler:    _Control_DeleteAuthoritative_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "resolver.proto",
}
