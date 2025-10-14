package record

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/cysec-dev/tls-golang-book/internal/common"
)

func TestNewTLSRecord(t *testing.T) {
	tests := []struct {
		name         string
		ContentType  common.ContentType
		payload      []byte
		want         *Record
		expectingErr bool
	}{
		{
			name:        "正常系：ハンドシェイクメッセージ",
			ContentType: common.Handshake,
			payload:     []byte("hello"),
			want: &Record{
				Type:    common.Handshake,
				Version: common.TLS_VERSION_1_2,
				Length:  5,
				Payload: []byte("hello"),
			},
			expectingErr: false,
		},
		{
			name:        "正常系：アプリケーションデータ",
			ContentType: common.ApplicationData,
			payload:     []byte{0x01, 0x02, 0x03},
			want: &Record{
				Type:    common.ApplicationData,
				Version: common.TLS_VERSION_1_2,
				Length:  3,
				Payload: []byte{0x01, 0x02, 0x03},
			},
			expectingErr: false,
		},
		{
			name:         "異常系：ペイロードが大きすぎる",
			ContentType:  common.ApplicationData,
			payload:      make([]byte, 16385),
			want:         nil,
			expectingErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewTLSRecord(tt.ContentType, tt.payload)
			if (err != nil) != tt.expectingErr {
				t.Errorf("NewTLSRecord() error = %v, expectingErr %v", err, tt.expectingErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewTLSRecord() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRecord_Marshal(t *testing.T) {
	tests := []struct {
		name string
		r    *Record
		want []byte
	}{
		{
			name: "正常系：ハンドシェイクメッセージ",
			r: &Record{
				Type:    common.Handshake,
				Version: common.TLS_VERSION_1_2,
				Length:  12,
				Payload: []byte("hello world!"),
			},
			want: []byte{
				0x16,
				0x03, 0x03,
				0x00, 0x0c,
				'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!',
			},
		},
		{
			name: "正常系：空のペイロード",
			r: &Record{
				Type:    common.Alert,
				Version: common.TLS_VERSION_1_2,
				Length:  0,
				Payload: []byte{},
			},
			want: []byte{
				0x15,
				0x03, 0x03,
				0x00, 0x00,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.r.Marshal(); !bytes.Equal(got, tt.want) {
				t.Errorf("Record.Marshal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseRecord(t *testing.T) {
	tests := []struct {
		name         string
		data         []byte
		want         *Record
		expectingErr bool
	}{
		{
			name: "正常系：ハンドシェイクメッセージ",
			data: []byte{
				0x16,
				0x03, 0x03,
				0x00, 0x05,
				't', 'e', 's', 't', '!',
			},
			want: &Record{
				Type:    common.Handshake,
				Version: common.TLS_VERSION_1_2,
				Length:  5,
				Payload: []byte("test!"),
			},
			expectingErr: false,
		},
		{
			name: "正常系：後続データが存在する場合",
			data: []byte{
				0x17,
				0x03, 0x03,
				0x00, 0x04,
				0x01, 0x02, 0x03, 0x04,
				0xaa, 0xbb, 0xcc,
			},
			want: &Record{
				Type:    common.ApplicationData,
				Version: common.TLS_VERSION_1_2,
				Length:  4,
				Payload: []byte{0x01, 0x02, 0x03, 0x04},
			},
			expectingErr: false,
		},
		{
			name:         "異常系：データがヘッダーサイズより短い",
			data:         []byte{0x16, 0x03, 0x03, 0x00},
			want:         nil,
			expectingErr: true,
		},
		{
			name:         "異常系：データがLengthフィールドの値より短い",
			data:         []byte{0x16, 0x03, 0x03, 0x00, 0x0a, 0x01, 0x02, 0x03},
			want:         nil,
			expectingErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRecord(tt.data)
			if (err != nil) != tt.expectingErr {
				t.Errorf("ParseRecord() error = %v, expectingErr %v", err, tt.expectingErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseRecord() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRecord_RoundTrip(t *testing.T) {
	t.Run("正常系：生成、マーシャリング、パースの一連の処理が正しく行われる", func(t *testing.T) {
		originalPayload := []byte("this is a round trip test")
		originalRecord, err := NewTLSRecord(common.ApplicationData, originalPayload)
		if err != nil {
			t.Fatalf("NewTLSRecord() failed: %v", err)
		}

		marshaledData := originalRecord.Marshal()

		parsedRecord, err := ParseRecord(marshaledData)
		if err != nil {
			t.Fatalf("ParseRecord() failed: %v", err)
		}

		if !reflect.DeepEqual(originalRecord, parsedRecord) {
			t.Errorf("Round trip failed. Original: %v, Parsed: %v", originalRecord, parsedRecord)
		}
	})
}
