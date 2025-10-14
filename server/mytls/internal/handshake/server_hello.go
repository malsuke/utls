package handshake

import (
	"github.com/refraction-networking/utls/server/mytls/internal/common"
	"github.com/refraction-networking/utls/server/mytls/internal/handshake/extensions"
)

/**
 * @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.3
 */
type ServerHello struct {
	ProtocolVersion   common.TLSVersion
	Random            [32]byte
	SessionID         []byte
	CipherSuite       common.CipherSuite
	CompressionMethod byte
	Extensions        []extensions.Extension
}

// func (sh *ServerHello) UnMarshal(data []byte) error {
// 	if len(data) < 38 {
// 		return fmt.Errorf("data too short for ServerHello: %d bytes", len(data))
// 	}
// 	sh.ProtocolVersion = common.TLSVersion(common.DecodeBytesToUint16(data[0:2]))
// 	copy(sh.Random[:], data[2:34])
// 	sessionIDLen := int(data[34])
// 	if len(data) < 35+sessionIDLen+3 {
// 		return fmt.Errorf("data too short for ServerHello with session ID length %d: %d bytes", sessionIDLen, len(data))
// 	}
// 	sh.SessionID = make([]byte, sessionIDLen)
// 	copy(sh.SessionID, data[35:35+sessionIDLen])
// 	sh.CipherSuite = common.CipherSuite(common.DecodeBytesToUint16(data[35+sessionIDLen : 37+sessionIDLen]))
// 	sh.CompressionMethod = data[37+sessionIDLen]
// 	if len(data) == 38+sessionIDLen {
// 		return nil
// 	}
// 	if len(data) < 40+sessionIDLen {
// 		return fmt.Errorf("data too short for ServerHello extensions with session ID length %d: %d bytes", sessionIDLen, len(data))
// 	}
// 	extensionsLength := int(common.DecodeBytesToUint16(data[38+sessionIDLen : 40+sessionIDLen]))
// 	if len(data) != 40+sessionIDLen+extensionsLength {
// 		return fmt.Errorf("data length mismatch for ServerHello extensions: expected %d, got %d", 40+sessionIDLen+extensionsLength, len(data))
// 	}
// 	extensionsData := data[40+sessionIDLen:]
// 	for len(extensionsData) > 0 {
// 		if len(extensionsData) < 4 {
// 			return fmt.Errorf("insufficient data for extension header: %d bytes", len(extensionsData))
// 		}
// 		extType := common.DecodeBytesToUint16(extensionsData[0:2])
// 		extLen := int(common.DecodeBytesToUint16(extensionsData[2:4]))
// 		if len(extensionsData) < 4+extLen {
// 			return fmt.Errorf("insufficient data for extension data: expected %d, got %d", extLen, len(extensionsData)-4)
// 		}
// 		extData := extensionsData[4 : 4+extLen]
// 		ext, err := extensions.UnMarshalExtension(extType, extData)
// 		if err != nil {
// 			return err
// 		}
// 		sh.Extensions = append(sh.Extensions, *ext)
// 		extensionsData = extensionsData[4+extLen:]
// 	}
// 	return nil
// }
