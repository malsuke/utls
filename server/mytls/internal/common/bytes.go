package common

import "encoding/binary"

func EncodeUint16ToBytes(v uint16) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, v)
	return buf
}

func DecodeBytesToUint16(data []byte) uint16 {
	return binary.BigEndian.Uint16(data)
}
