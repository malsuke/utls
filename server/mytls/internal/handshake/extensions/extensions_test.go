package extensions_test

import (
	"bytes"
	"testing"

	"github.com/refraction-networking/utls/server/mytls/internal/common"
	"github.com/refraction-networking/utls/server/mytls/internal/handshake/extensions"
)

func TestExtensionMarshal(t *testing.T) {
	correctPayload := []byte{0x00, 0x0c, 0x00, 0x00, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74}
	ext := &extensions.Extension{
		Type:    common.ServerNameExtensionType,
		Payload: correctPayload,
	}
	marshaled := ext.Marshal()
	expected := []byte{
		0x00, 0x00, // ExtensionType
		0x00, 0x0e, // Payload Length (14)
	}
	expected = append(expected, correctPayload...)

	if !bytes.Equal(marshaled, expected) {
		t.Errorf("Extension.Marshal() = %x, want %x", marshaled, expected)
	}
}

func TestExtensionsMarshal(t *testing.T) {
	correctPayload := []byte{0x00, 0x0c, 0x00, 0x00, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74}
	exts := &extensions.Extensions{
		Extensions: []*extensions.Extension{
			{
				Type:    common.ServerNameExtensionType,
				Payload: correctPayload,
			},
			{
				Type:    common.SupportedGroupsExtensionType,
				Payload: []byte{0x00, 0x02, 0x00, 0x1d},
			},
		},
	}
	marshaled := exts.Marshal()

	expectedServerName := []byte{
		0x00, 0x00, // ExtensionType
		0x00, 0x0e, // Payload Length
	}
	expectedServerName = append(expectedServerName, correctPayload...)

	expectedSupportedGroups := []byte{
		0x00, 0x0a, // ExtensionType
		0x00, 0x04, // Payload Length
		0x00, 0x02, 0x00, 0x1d, // Payload
	}
	expected := append(expectedServerName, expectedSupportedGroups...)

	if !bytes.Equal(marshaled, expected) {
		t.Errorf("Extensions.Marshal() = %x, want %x", marshaled, expected)
	}
}

func TestUnMarshalExtension(t *testing.T) {
	cases := []struct {
		name          string
		input         []byte
		expectedType  common.ExtensionType
		expectedError bool
	}{
		{
			name: "Valid ServerNameExtension",
			input: []byte{
				0x00, 0x00, // ExtensionType: server_name
				0x00, 0x0e, // Length
				0x00, 0x0c, 0x00, 0x00, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74,
			},
			expectedType:  common.ServerNameExtensionType,
			expectedError: false,
		},
		{
			name: "Valid SupportedGroupsExtension",
			input: []byte{
				0x00, 0x0a, // ExtensionType: supported_groups
				0x00, 0x04, // Length
				0x00, 0x02, 0x00, 0x1d,
			},
			expectedType:  common.SupportedGroupsExtensionType,
			expectedError: false,
		},
		{
			name: "Unknown ExtensionType",
			input: []byte{
				0xff, 0xff, // Unknown ExtensionType
				0x00, 0x01, // Length
				0x00,
			},
			expectedError: true,
		},
		{
			name:          "Data too short",
			input:         []byte{0x00, 0x00, 0x00},
			expectedError: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ext, err := extensions.UnMarshalExtension(c.input)

			if c.expectedError {
				if err == nil {
					t.Fatalf("expected an error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if ext.Type != c.expectedType {
				t.Errorf("expected extension type %v, but got %v", c.expectedType, ext.Type)
			}

			expectedPayload := c.input[4:]
			if !bytes.Equal(ext.Payload, expectedPayload) {
				t.Errorf("expected payload %x, but got %x", expectedPayload, ext.Payload)
			}
		})
	}
}

func TestUnMarshalExtensions(t *testing.T) {
	data := []byte{
		0x00, 0x00, // ExtensionType: server_name
		0x00, 0x0e, // Length
		0x00, 0x0c, 0x00, 0x00, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74,
		0x00, 0x0a, // ExtensionType: supported_groups
		0x00, 0x04, // Length
		0x00, 0x02, 0x00, 0x1d,
	}

	exts, err := extensions.UnMarshalExtensions(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(exts) != 2 {
		t.Fatalf("expected 2 extensions, but got %d", len(exts))
	}

	if exts[0].Type != common.ServerNameExtensionType {
		t.Errorf("expected first extension type %v, but got %v", common.ServerNameExtensionType, exts[0].Type)
	}

	expectedPayload1 := data[4:18]
	if !bytes.Equal(exts[0].Payload, expectedPayload1) {
		t.Errorf("expected first extension payload %x, but got %x", expectedPayload1, exts[0].Payload)
	}

	if exts[1].Type != common.SupportedGroupsExtensionType {
		t.Errorf("expected second extension type %v, but got %v", common.SupportedGroupsExtensionType, exts[1].Type)
	}

	expectedPayload2 := data[22:]
	if !bytes.Equal(exts[1].Payload, expectedPayload2) {
		t.Errorf("expected second extension payload %x, but got %x", expectedPayload2, exts[1].Payload)
	}
}
