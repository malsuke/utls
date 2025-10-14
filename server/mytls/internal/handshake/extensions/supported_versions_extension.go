package extensions

import (
	"encoding/binary"

	"github.com/refraction-networking/utls/server/mytls/internal/common"
)

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.1
 */
func NewSupportedVersionsExtension(versions []uint16) *Extension {
	// The vector of TLS protocol versions is prefixed with a uint8 length field.
	payload := make([]byte, 1+len(versions)*2)
	payload[0] = byte(len(versions) * 2)
	offset := 1
	for _, v := range versions {
		binary.BigEndian.PutUint16(payload[offset:], v)
		offset += 2
	}

	return &Extension{
		Type:    common.SupportedVersionsExtensionType,
		Payload: payload,
	}
}
