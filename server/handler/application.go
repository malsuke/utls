package handler

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/labstack/echo/v4"
	utls "github.com/refraction-networking/utls"
	"github.com/refraction-networking/utls/server/openapi"
)

// TeeConn wraps a net.Conn to tee its reads into a buffer.
type TeeConn struct {
	net.Conn
	readBuffer *bytes.Buffer
}

// NewTeeConn creates a new TeeConn.
func NewTeeConn(conn net.Conn) *TeeConn {
	return &TeeConn{
		Conn:       conn,
		readBuffer: new(bytes.Buffer),
	}
}

// Read reads data from the connection and writes a copy to the buffer.
func (c *TeeConn) Read(p []byte) (n int, err error) {
	n, err = c.Conn.Read(p)
	if n > 0 {
		// The buffer captures everything read from the underlying connection.
		c.readBuffer.Write(p[:n])
	}
	return
}

// GetReadData returns all data that was read from the connection.
func (c *TeeConn) GetReadData() []byte {
	return c.readBuffer.Bytes()
}

// extractApplicationData parses a raw byte stream of TLS records and returns the
// slice starting from the first Application Data record.
func extractApplicationData(data []byte) []byte {
	offset := 0
	for offset < len(data) {
		if offset+5 > len(data) {
			// Not enough data for a full record header
			break
		}
		// TLS record header:
		//   byte 0: content type
		//   byte 1, 2: version
		//   byte 3, 4: length
		contentType := data[offset]
		length := int(data[offset+3])<<8 | int(data[offset+4])

		if contentType == 23 { // Application Data
			// Found the first application data record.
			// Return the slice from this point to the end.
			return data[offset:]
		}

		// Move to the next record
		recordEnd := offset + 5 + length
		if recordEnd > len(data) {
			// Incomplete record in buffer
			break
		}
		offset = recordEnd
	}
	// No application data found
	return nil
}

func (s Server) PostTlsApplication(ctx echo.Context) error {
	var payload openapi.ApplicationRequest
	if err := ctx.Bind(&payload); err != nil {
		return ctx.JSON(400, "Invalid payload")
	}

	// 接続先ホストはServerNameを使い、ポートは443をデフォルトとする
	conn, err := net.DialTimeout("tcp", payload.ServerName+":443", 5*time.Second)
	if err != nil {
		return ctx.JSON(500, fmt.Sprintf("net.Dial error: %v", err))
	}
	defer conn.Close()

	// Wrap the connection to tee the reads
	teeConn := NewTeeConn(conn)

	spec, err := createClientHelloSpec(payload)
	if err != nil {
		return ctx.JSON(400, fmt.Sprintf("createClientHelloSpec error: %v", err))
	}

	var serverResponse []byte
	config := &utls.Config{
		ServerName:     payload.ServerName,
		ServerResponse: &serverResponse,
		KeyLogWriter:   os.Stderr,
		MinVersion:     utls.VersionTLS13,
		MaxVersion:     utls.VersionTLS13,
	}
	uconn := utls.UClient(teeConn, config, utls.HelloCustom)
	if err := uconn.ApplyPreset(spec); err != nil {
		return ctx.JSON(500, fmt.Sprintf("ApplyPreset error: %v", err))
	}

	clientRandom, err := hex.DecodeString(payload.ClientRandom)
	if err != nil {
		return ctx.JSON(400, fmt.Sprintf("Invalid ClientRandom: %v", err))
	}
	if err := uconn.SetClientRandom(clientRandom); err != nil {
		return ctx.JSON(500, fmt.Sprintf("SetClientRandom error: %v", err))
	}

	if err := uconn.Handshake(); err != nil {
		return ctx.JSON(500, fmt.Sprintf("uconn.Handshake() error: %v", err))
	}

	var httpResponse []byte
	var allRawData []byte
	if payload.ApplicationData != nil {
		_, err = uconn.Write([]byte(*payload.ApplicationData))
		if err != nil {
			return ctx.JSON(500, fmt.Sprintf("uconn.Write() error: %v", err))
		}

		httpResponse, err = io.ReadAll(uconn)
		if err != nil {
			// Log error but don't fail the request entirely
			fmt.Printf("io.ReadAll(uconn) error: %v\n", err)
		}
		// Get all the raw data captured by the tee
		allRawData = teeConn.GetReadData()
	}

	// Extract only the application data part from the raw stream
	encryptedApplicationData := extractApplicationData(allRawData)

	appResponse := openapi.ApplicationResponse{
		RawClientHello:                          hex.EncodeToString(convertRecordbytes(utls.ClientHelloRaw)),
		RawServerResponse:                       hex.EncodeToString(serverResponse),
		RawServerResponseDecoded:                hex.EncodeToString(utls.FullRecordBytes),
		RawServerApplicationDataResponse:        hex.EncodeToString(encryptedApplicationData),
		RawServerApplicationDataResponseDecoded: string(httpResponse),
	}

	return ctx.JSON(200, appResponse)
}
