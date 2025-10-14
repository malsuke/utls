package extensions

import "github.com/refraction-networking/utls/server/mytls/internal/common"

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.9
 */
func NewPskKeyExchangeModesExtension() *Extension {
	var payload []byte
	payload = append(payload, 0x01) // PskKeyExchangeModes length
	payload = append(payload, 0x01) // psk_ke

	return &Extension{
		Type:    common.PSKKeyExchangeModesExtensionType,
		Payload: payload,
	}
}
