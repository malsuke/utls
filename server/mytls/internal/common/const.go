package common

import "fmt"

type ContentType uint8

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-5.1
 */
const (
	Invalid          ContentType = 0x00
	ChangeCipherSpec ContentType = 0x14
	Alert            ContentType = 0x15
	Handshake        ContentType = 0x16
	ApplicationData  ContentType = 0x17
)

type TLSVersion uint16

const (
	TLS_VERSION_1_0 TLSVersion = 0x0301
	TLS_VERSION_1_1 TLSVersion = 0x0302
	TLS_VERSION_1_2 TLSVersion = 0x0303
	TLS_VERSION_1_3 TLSVersion = 0x0304
)

func (v TLSVersion) String() string {
	switch v {
	case TLS_VERSION_1_0:
		return "TLS 1.0"
	case TLS_VERSION_1_1:
		return "TLS 1.1"
	case TLS_VERSION_1_2:
		return "TLS 1.2"
	case TLS_VERSION_1_3:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown TLS version: 0x%04x", uint16(v))
	}
}

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-4
 */
type HandshakeType uint8

const (
	ClientHello HandshakeType = 0x01
	ServerHello HandshakeType = 0x02
)

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.4
 */
type CipherSuite uint16

const (
	TLS_AES_128_GCM_SHA256       CipherSuite = 0x1301
	TLS_AES_256_GCM_SHA384       CipherSuite = 0x1302
	TLS_CHACHA20_POLY1305_SHA256 CipherSuite = 0x1303
	TLS_AES_128_CCM_SHA256       CipherSuite = 0x1304
	TLS_AES_128_CCM_8_SHA256     CipherSuite = 0x1305
)

func (cs CipherSuite) String() string {
	switch cs {
	case TLS_AES_128_GCM_SHA256:
		return "TLS_AES_128_GCM_SHA256"
	case TLS_AES_256_GCM_SHA384:
		return "TLS_AES_256_GCM_SHA384"
	case TLS_CHACHA20_POLY1305_SHA256:
		return "TLS_CHACHA20_POLY1305_SHA256"
	case TLS_AES_128_CCM_SHA256:
		return "TLS_AES_128_CCM_SHA256"
	case TLS_AES_128_CCM_8_SHA256:
		return "TLS_AES_128_CCM_8_SHA256"
	default:
		return fmt.Sprintf("Unknown CipherSuite: 0x%04x", uint16(cs))
	}
}

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
 */
type ExtensionType uint16

const (
	ServerNameExtensionType          ExtensionType = 0x0000
	SupportedGroupsExtensionType     ExtensionType = 0x000a
	SignatureAlgorithmsExtensionType ExtensionType = 0x000d
	KeyShareExtensionType            ExtensionType = 0x0033
	SupportedVersionsExtensionType   ExtensionType = 0x002b
	PSKKeyExchangeModesExtensionType ExtensionType = 0x002d
)

func (et ExtensionType) String() string {
	switch et {
	case ServerNameExtensionType:
		return "ServerName"
	case SupportedGroupsExtensionType:
		return "SupportedGroups"
	case SignatureAlgorithmsExtensionType:
		return "SignatureAlgorithms"
	case KeyShareExtensionType:
		return "KeyShare"
	case SupportedVersionsExtensionType:
		return "SupportedVersions"
	case PSKKeyExchangeModesExtensionType:
		return "PSKKeyExchangeModes"
	default:
		return fmt.Sprintf("Unknown ExtensionType: 0x%04x", uint16(et))
	}
}

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.7
 */
type SupportedGroupsType uint16

const (
	X25519 SupportedGroupsType = 0x001d
)

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.3
 */
type SignatureAlgorithmType uint16

const (
	Ed25519 SignatureAlgorithmType = 0x0807
)
