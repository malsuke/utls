package extensions

import "github.com/refraction-networking/utls/server/mytls/internal/common"

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.7
 */
func NewSupportedGroupsExtension() *Extension {
	var payload []byte
	payload = append(payload, 0x00, 0x02)
	payload = append(payload, common.EncodeUint16ToBytes(uint16(common.X25519))...)

	return &Extension{
		Type:    common.SupportedGroupsExtensionType,
		Payload: payload,
	}
}
