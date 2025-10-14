package extensions

import (
	"fmt"

	"github.com/cysec-dev/tls-golang-book/internal/common"
)

type Extension struct {
	Type    common.ExtensionType
	Payload []byte
}

func (e *Extension) Marshal() []byte {
	var result []byte
	result = append(result, common.EncodeUint16ToBytes(uint16(e.Type))...)
	result = append(result, common.EncodeUint16ToBytes(uint16(len(e.Payload)))...)
	result = append(result, e.Payload...)
	return result
}

type Extensions struct {
	Extensions []*Extension
}

func (e *Extensions) Marshal() []byte {
	var result []byte
	for _, ext := range e.Extensions {
		result = append(result, ext.Marshal()...)
	}
	return result
}

func (e *Extensions) Length() int {
	var length int
	for _, ext := range e.Extensions {
		length += 4 + len(ext.Payload)
	}
	return length
}

func UnMarshalExtensions(data []byte) ([]*Extension, error) {
	var extensions []*Extension
	for len(data) > 0 {
		if len(data) < 4 {
			return nil, fmt.Errorf("data too short for extension: %d bytes", len(data))
		}
		extLength := int(common.DecodeBytesToUint16(data[2:4])) + 4
		if len(data) < extLength {
			return nil, fmt.Errorf("data too short for extension: %d bytes", len(data))
		}
		ext, err := UnMarshalExtension(data[:extLength])
		if err != nil {
			return nil, err
		}
		extensions = append(extensions, ext)
		data = data[extLength:]
	}
	return extensions, nil
}

func UnMarshalExtension(data []byte) (*Extension, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("data too short for extension: %d bytes", len(data))
	}

	switch common.ExtensionType(common.DecodeBytesToUint16(data[0:2])) {
	case common.ServerNameExtensionType:
		return &Extension{
			Type:    common.ServerNameExtensionType,
			Payload: data[4:],
		}, nil
	case common.SupportedGroupsExtensionType:
		return &Extension{
			Type:    common.SupportedGroupsExtensionType,
			Payload: data[4:],
		}, nil
	case common.SignatureAlgorithmsExtensionType:
		return &Extension{
			Type:    common.SignatureAlgorithmsExtensionType,
			Payload: data[4:],
		}, nil
	case common.KeyShareExtensionType:
		return &Extension{
			Type:    common.KeyShareExtensionType,
			Payload: data[4:],
		}, nil
	case common.SupportedVersionsExtensionType:
		return &Extension{
			Type:    common.SupportedVersionsExtensionType,
			Payload: data[4:],
		}, nil
	case common.PSKKeyExchangeModesExtensionType:
		return &Extension{
			Type:    common.PSKKeyExchangeModesExtensionType,
			Payload: data[4:],
		}, nil
	default:
		return nil, fmt.Errorf("unknown extension type: 0x%04x", common.DecodeBytesToUint16(data[0:2]))
	}
}
