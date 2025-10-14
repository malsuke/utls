package handshake

import (
	"fmt"

	"github.com/refraction-networking/utls/server/mytls/internal/common"
	"github.com/refraction-networking/utls/server/mytls/internal/crypto"
	"github.com/refraction-networking/utls/server/mytls/internal/handshake/extensions"
)

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
 */
type ClientHello struct {
	ProtocolVersion          common.TLSVersion
	Random                   [32]byte
	LegacySessionID          []byte
	CipherSuites             []common.CipherSuite
	LegacyCompressionMethods []byte
	Extensions               []extensions.Extension
}

func NewClientHello(extensions []extensions.Extension) (*ClientHello, error) {
	random, err := crypto.GenerateRandom32Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ClientHello random: %w", err)
	}
	return &ClientHello{
		ProtocolVersion:          common.TLS_VERSION_1_2,
		Random:                   random,
		LegacySessionID:          []byte{},
		CipherSuites:             []common.CipherSuite{common.TLS_AES_128_GCM_SHA256},
		LegacyCompressionMethods: []byte{0x00},
		Extensions:               extensions,
	}, nil
}

func (ch *ClientHello) Marshal() []byte {
	var result []byte
	result = append(result, common.EncodeUint16ToBytes(uint16(ch.ProtocolVersion))...)
	result = append(result, ch.Random[:]...)
	result = append(result, byte(len(ch.LegacySessionID)))
	result = append(result, ch.LegacySessionID...)

	// CipherSuites
	cipherSuitesLength := len(ch.CipherSuites) * 2
	result = append(result, byte(cipherSuitesLength>>8), byte(cipherSuitesLength&0xff))
	for _, cs := range ch.CipherSuites {
		result = append(result, byte(cs>>8), byte(cs&0xff))
	}

	// LegacyCompressionMethods
	result = append(result, byte(len(ch.LegacyCompressionMethods)))
	result = append(result, ch.LegacyCompressionMethods...)

	// Extensions
	var extensionsBytes []byte
	for _, ext := range ch.Extensions {
		extensionsBytes = append(extensionsBytes, ext.Marshal()...)
	}
	extensionsLength := len(extensionsBytes)
	result = append(result, byte(extensionsLength>>8), byte(extensionsLength&0xff))
	result = append(result, extensionsBytes...)

	return result
}
