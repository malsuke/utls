package extensions

import "github.com/refraction-networking/utls/server/mytls/internal/common"

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.1
 */
func NewSupportedVersionsExtension() *Extension {
	var payload []byte
	payload = append(payload, 0x02)
	payload = append(payload, 0x03, 0x04)

	return &Extension{
		Type:    common.SupportedVersionsExtensionType,
		Payload: payload,
	}
}
