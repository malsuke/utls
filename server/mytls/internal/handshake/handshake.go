package handshake

import "github.com/cysec-dev/tls-golang-book/internal/common"

type Handshake struct {
	HandshakeType common.HandshakeType
	Length        [3]byte
	Body          []byte
}

func NewHandshake(handshakeType common.HandshakeType, body []byte) *Handshake {
	length := len(body)
	if length > 0xffffff {
		return nil
	}
	return &Handshake{
		HandshakeType: handshakeType,
		Length:        [3]byte{byte(length >> 16), byte((length >> 8) & 0xff), byte(length & 0xff)},
		Body:          body,
	}
}

func (h *Handshake) Marshal() []byte {
	var result []byte
	result = append(result, byte(h.HandshakeType))
	result = append(result, h.Length[0], h.Length[1], h.Length[2])
	result = append(result, h.Body...)
	return result
}
