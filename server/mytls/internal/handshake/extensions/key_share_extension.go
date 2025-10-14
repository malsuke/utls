package extensions

import (
	"encoding/binary"

	"github.com/refraction-networking/utls/server/mytls/internal/common"
)

// KeyShareEntry は、Key Share Extension 内の単一のエントリを表します。
type KeyShareEntry struct {
	Group       uint16
	KeyExchange []byte
}

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8
 */
func NewKeyShareExtension(clientShares []KeyShareEntry) *Extension {
	var keyShareBytes []byte
	for _, share := range clientShares {
		entryBytes := make([]byte, 4+len(share.KeyExchange))
		binary.BigEndian.PutUint16(entryBytes[0:], share.Group)
		binary.BigEndian.PutUint16(entryBytes[2:], uint16(len(share.KeyExchange)))
		copy(entryBytes[4:], share.KeyExchange)
		keyShareBytes = append(keyShareBytes, entryBytes...)
	}

	// The client_shares vector is prefixed with a uint16 length field.
	payload := make([]byte, 2+len(keyShareBytes))
	binary.BigEndian.PutUint16(payload[0:], uint16(len(keyShareBytes)))
	copy(payload[2:], keyShareBytes)

	return &Extension{
		Type:    common.KeyShareExtensionType,
		Payload: payload,
	}
}
