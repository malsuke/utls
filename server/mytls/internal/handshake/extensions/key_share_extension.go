package extensions

import "github.com/cysec-dev/tls-golang-book/internal/common"

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8
 */
func NewKeyShareExtension(publicKey []byte) *Extension {
	var payload []byte
	keyShareEntryLength := 2 + 2 + len(publicKey) // group + key_exchange_length + key_exchange

	// client_shares length (2 bytes)
	payload = append(payload, byte(keyShareEntryLength>>8), byte(keyShareEntryLength&0xff))
	// group: x25519 (0x001d)
	payload = append(payload, common.EncodeUint16ToBytes(uint16(common.X25519))...)
	// key_exchange length (2 bytes)
	payload = append(payload, byte(len(publicKey)>>8), byte(len(publicKey)&0xff))
	// key_exchange (public key)
	payload = append(payload, publicKey...)

	return &Extension{
		Type:    common.KeyShareExtensionType,
		Payload: payload,
	}
}
