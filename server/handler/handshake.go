package handler

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	utls "github.com/refraction-networking/utls"
	"github.com/refraction-networking/utls/server/openapi"
)

type Server struct{}

func (s Server) PostTlsHandshake(ctx echo.Context) error {
	var payload openapi.HandshakeRequest
	if err := ctx.Bind(&payload); err != nil {
		return ctx.JSON(400, "Invalid payload")
	}

	var serverResponse []byte
	conn, err := net.DialTimeout("tcp", payload.Server+":"+fmt.Sprintf("%d", *payload.Port), 5*time.Second)
	if err != nil {
		fmt.Printf("net.Dial error: %v\n", err)
		return ctx.JSON(500, "No")
	}
	defer conn.Close()

	spec := createClientHelloSpec(payload)

	config := &utls.Config{
		ServerName:     payload.Server,
		ServerResponse: &serverResponse,
		KeyLogWriter:   os.Stderr,
		MinVersion:     utls.VersionTLS13,
		MaxVersion:     utls.VersionTLS13,
	}
	uconn := utls.UClient(conn, config, utls.HelloCustom)
	if err := uconn.ApplyPreset(&spec); err != nil {
		fmt.Printf("ApplyPreset error: %v\n", err)
		return ctx.JSON(500, "No")
	}

	if err := uconn.SetClientRandom([]byte(payload.ClientRandom)); err != nil {
		fmt.Printf("SetClientRandom error: %v\n", err)
		return ctx.JSON(500, "No")
	}

	if err := uconn.Handshake(); err != nil {
		fmt.Printf("uconn.Handshake() error: %v\n", err)
		if serverResponse != nil {
			fmt.Println("--- ServerResponse bytes on error ---")
			fmt.Print(hex.Dump(serverResponse))
			fmt.Println("-------------------------------------")
		}
		return ctx.JSON(500, "No")
	}

	fmt.Print(hex.Dump(convertRecordbytes(utls.ClientHelloRaw)))
	fmt.Println("✅ TLS Handshake successful")

	if serverResponse != nil {
		fmt.Println("--- ServerResponse bytes ---")
		fmt.Print(hex.Dump(serverResponse))
		fmt.Println("--------------------------")
	}

	requestBuilder := &strings.Builder{}
	requestBuilder.WriteString("GET / HTTP/1.1\r\n")
	requestBuilder.WriteString("Host: " + payload.Server + "\r\n")
	requestBuilder.WriteString("User-Agent: my-raw-client/1.0\r\n")
	requestBuilder.WriteString("Connection: close\r\n")
	requestBuilder.WriteString("\r\n")

	request := requestBuilder.String()
	fmt.Println("--- Sending Request ---")
	fmt.Print(request)
	fmt.Println("-----------------------")

	_, err = uconn.Write([]byte(request))
	if err != nil {
		fmt.Printf("uconn.Write() error: %v\n", err)
		return ctx.JSON(500, "No")
	}

	response, err := io.ReadAll(uconn)
	if err != nil {
		fmt.Printf("io.ReadAll(uconn) error: %v\n", err)
		return ctx.JSON(500, "No")
	}

	fmt.Println("\n--- Raw Response ---")
	fmt.Println(string(response))
	fmt.Println("--------------------")

	return ctx.JSON(200, "ok")
}

func createClientHelloSpec(payload openapi.HandshakeRequest) utls.ClientHelloSpec {
	keyShares := make([]utls.KeyShare, len(payload.KeyShares))

	for i, v := range payload.KeyShares {
		keyShares[i] = utls.KeyShare{
			Group: utls.CurveID(stringToUint16(*v.Group)),
			// Data:  []byte(v.Data),
		}
	}

	var cipherSuites []uint16 = make([]uint16, len(payload.CipherSuites))
	for i, v := range payload.CipherSuites {
		cipherSuites[i] = stringToUint16(v)
	}

	var supportedCurves []utls.CurveID = make([]utls.CurveID, len(payload.SupportedGroups))
	for i, v := range payload.SupportedGroups {
		supportedCurves[i] = utls.CurveID(stringToUint16(v))
	}

	var supportedSignatureAlgorithms = make([]utls.SignatureScheme, len(payload.SignatureAlgorithms))
	for i, v := range payload.SignatureAlgorithms {
		supportedSignatureAlgorithms[i] = utls.SignatureScheme(stringToUint16(v))
	}

	var supportedTLSVersions []uint16 = make([]uint16, len(payload.TlsVersions))
	for i, v := range payload.TlsVersions {
		supportedTLSVersions[i] = stringToUint16(v)
	}

	spec := utls.ClientHelloSpec{
		CipherSuites: cipherSuites,
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{ServerName: payload.ServerName},
			&utls.SupportedCurvesExtension{ // supported_groupsと同じ
				Curves: supportedCurves,
			},
			&utls.KeyShareExtension{KeyShares: keyShares},
			&utls.SignatureAlgorithmsExtension{
				SupportedSignatureAlgorithms: supportedSignatureAlgorithms,
			},
			&utls.SupportedVersionsExtension{Versions: supportedTLSVersions},
		},
	}

	return spec
}

/**
 * 0xから始まる16進数文字列をuint16に変換する
 * 例: "0x1301" -> 4865
 */
func stringToUint16(s string) uint16 {
	var result uint16
	_, err := fmt.Sscanf(s, "0x%04x", &result)
	if err != nil {
		return 0
	}
	return result
}

// ClientHelloRawをRecord Layerの形式に変換する
func convertRecordbytes(b []byte) []byte {
	record := make([]byte, 5+len(b))
	record[0] = 0x16                // Content Type: Handshake
	record[1] = 0x03                // Version: TLS 1.2 (for compatibility)
	record[2] = 0x01                // Version: TLS 1.2 (for compatibility)
	record[3] = byte(len(b) >> 8)   // Length (high byte)
	record[4] = byte(len(b) & 0xff) // Length (low byte)
	copy(record[5:], b)             // Copy ClientHello bytes
	return record
}
