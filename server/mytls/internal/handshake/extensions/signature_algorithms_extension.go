package extensions

import "github.com/cysec-dev/tls-golang-book/internal/common"

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.3
 */
func NewSignatureAlgorithmsExtension() *Extension {
	var payload []byte
	payload = append(payload, 0x00, 0x08)                                     // SignatureAlgorithms length
	payload = append(payload, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x08, 0x07) // ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, rsa_pkcs1_sha256, ed25519

	return &Extension{
		Type:    common.SignatureAlgorithmsExtensionType,
		Payload: payload,
	}
}
