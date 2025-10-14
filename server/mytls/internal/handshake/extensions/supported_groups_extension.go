package extensions

import (
	"encoding/binary"

	"github.com/refraction-networking/utls/server/mytls/internal/common"
)

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.7
 */
func NewSupportedGroupsExtension(groups []uint16) *Extension {
	// The vector of named groups is prefixed with a uint16 length field.
	payload := make([]byte, 2+len(groups)*2)
	binary.BigEndian.PutUint16(payload[0:], uint16(len(groups)*2))
	offset := 2
	for _, g := range groups {
		binary.BigEndian.PutUint16(payload[offset:], g)
		offset += 2
	}

	return &Extension{
		Type:    common.SupportedGroupsExtensionType,
		Payload: payload,
	}
}
