package record

import (
	"encoding/binary"
	"fmt"

	"github.com/refraction-networking/utls/server/mytls/internal/common"
)

type Record struct {
	Type    common.ContentType
	Version common.TLSVersion
	Length  uint16
	Payload []byte
}

func NewTLSRecord(ContentType common.ContentType, payload []byte) (*Record, error) {
	if len(payload) > 16384 {
		return nil, fmt.Errorf("payload too large: %d bytes", len(payload))
	}

	return &Record{
		Type:    ContentType,
		Version: common.TLS_VERSION_1_2,
		Length:  uint16(len(payload)),
		Payload: payload,
	}, nil
}

func (r *Record) Marshal() []byte {
	var result []byte
	result = append(result, byte(r.Type))
	result = append(result, common.EncodeUint16ToBytes(uint16(r.Version))...)
	result = append(result, common.EncodeUint16ToBytes(r.Length)...)
	result = append(result, r.Payload...)
	return result
}

func ParseRecord(data []byte) (*Record, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("parse error: data too short, expected at least 5 bytes, got %d", len(data))
	}
	ContentType := common.ContentType(data[0])
	version := common.TLSVersion(binary.BigEndian.Uint16(data[1:3]))
	length := binary.BigEndian.Uint16(data[3:5])

	if len(data)-5 < int(length) {
		return nil, fmt.Errorf("parse error: data length mismatch, expected %d bytes, got %d", length, len(data)-5)
	}

	return &Record{
		Type:    ContentType,
		Version: version,
		Length:  length,
		Payload: data[5 : 5+length],
	}, nil
}
