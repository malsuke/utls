package extensions

import "github.com/refraction-networking/utls/server/mytls/internal/common"

/**
 * @see https://datatracker.ietf.org/doc/html/rfc6066#section-3
 */
func NewServerNameExtension(servername string) *Extension {
	nameBytes := []byte(servername)
	nameLength := len(nameBytes)

	// ServerNameList length = NameType(1) + HostName length(2) + HostName
	serverNameListLength := 1 + 2 + nameLength

	var payload []byte
	// ServerNameList length (2 bytes)
	payload = append(payload, byte(serverNameListLength>>8), byte(serverNameListLength&0xff))
	// NameType: host_name (0)
	payload = append(payload, 0x00)
	// HostName length (2 bytes)
	payload = append(payload, byte(nameLength>>8), byte(nameLength&0xff))
	// HostName (bytes)
	payload = append(payload, nameBytes...)

	return &Extension{
		Type:    common.ServerNameExtensionType,
		Payload: payload,
	}
}
