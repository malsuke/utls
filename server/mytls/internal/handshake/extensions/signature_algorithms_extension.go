package extensions

import (
	"encoding/binary"

	"github.com/refraction-networking/utls/server/mytls/internal/common"
)

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.3
 */
func NewSignatureAlgorithmsExtension(schemes []uint16) *Extension {
	// The vector of signature schemes is prefixed with a uint16 length field.
	payload := make([]byte, 2+len(schemes)*2)
	binary.BigEndian.PutUint16(payload[0:], uint16(len(schemes)*2))
	offset := 2
	for _, s := range schemes {
		binary.BigEndian.PutUint16(payload[offset:], s)
		offset += 2
	}

	return &Extension{
		Type:    common.SignatureAlgorithmsExtensionType,
		Payload: payload,
	}
}
