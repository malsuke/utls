package handler

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/labstack/echo/v4"
	utls "github.com/refraction-networking/utls"
	"github.com/refraction-networking/utls/server/mytls"
	"github.com/refraction-networking/utls/server/openapi"
)

type Server struct{}

// handleBadRequest は、リクエスト処理中にエラーが発生した場合に、
// mytlsでの通信試行結果を含めたエラーレスポンスを返します。
func handleBadRequest(ctx echo.Context, originalError error, params openapi.TlsClientParameters) error {
	sent, received, mytlsErr := mytls.PerformHandshake(params)

	response := map[string]interface{}{
		"error":          "Bad Request",
		"original_error": originalError.Error(),
		"mytls_sent":     hex.EncodeToString(sent),
		"mytls_received": hex.EncodeToString(received),
	}
	if mytlsErr != nil {
		response["mytls_error"] = mytlsErr.Error()
	}

	return ctx.JSON(400, response)
}

func (s Server) PostTlsHandshake(ctx echo.Context) error {
	var payload openapi.HandshakeRequest
	if err := ctx.Bind(&payload); err != nil {
		return handleBadRequest(ctx, fmt.Errorf("invalid payload: %w", err), payload)
	}

	spec, err := createClientHelloSpec(payload)
	if err != nil {
		return handleBadRequest(ctx, err, payload)
	}

	clientRandom, err := hex.DecodeString(payload.ClientRandom)
	if err != nil {
		return handleBadRequest(ctx, fmt.Errorf("invalid ClientRandom: %w", err), payload)
	}

	// 接続先ホストはServerNameを使い、ポートは443をデフォルトとする
	conn, err := net.DialTimeout("tcp", payload.ServerName+":443", 5*time.Second)
	if err != nil {
		return ctx.JSON(500, fmt.Sprintf("net.Dial error: %v", err))
	}
	defer conn.Close()

	var serverResponse []byte
	config := &utls.Config{
		ServerName:     payload.ServerName,
		ServerResponse: &serverResponse,
		KeyLogWriter:   os.Stderr,
		MinVersion:     utls.VersionTLS13,
		MaxVersion:     utls.VersionTLS13,
	}
	uconn := utls.UClient(conn, config, utls.HelloCustom)
	if err := uconn.ApplyPreset(spec); err != nil {
		return handleBadRequest(ctx, fmt.Errorf("invalid payload: %w", err), payload)
		// return ctx.JSON(500, fmt.Sprintf("ApplyPreset error: %v", err))
	}

	if err := uconn.SetClientRandom(clientRandom); err != nil {
		return handleBadRequest(ctx, fmt.Errorf("invalid payload: %w", err), payload)
		// return ctx.JSON(500, fmt.Sprintf("SetClientRandom error: %v", err))
	}

	if err := uconn.Handshake(); err != nil {
		return handleBadRequest(ctx, fmt.Errorf("invalid payload: %w", err), payload)
		// return ctx.JSON(500, fmt.Sprintf("uconn.Handshake() error: %v", err))
	}

	response := openapi.HandshakeResponse{
		RawClientHello:           hex.EncodeToString(convertRecordbytes(utls.ClientHelloRaw)),
		RawServerResponse:        hex.EncodeToString(serverResponse),
		RawServerResponseDecoded: hex.EncodeToString(utls.FullRecordBytes),
	}

	return ctx.JSON(200, response)
}

func createClientHelloSpec(payload openapi.TlsClientParameters) (*utls.ClientHelloSpec, error) {
	keyShares := make([]utls.KeyShare, len(payload.KeyShares))
	for i, v := range payload.KeyShares {
		val, err := stringToUint16(v)
		if err != nil {
			return nil, fmt.Errorf("invalid key share: %s", v)
		}
		keyShares[i] = utls.KeyShare{
			Group: utls.CurveID(val),
		}
	}

	cipherSuites := make([]uint16, len(payload.CipherSuites))
	for i, v := range payload.CipherSuites {
		val, err := stringToUint16(v)
		if err != nil {
			return nil, fmt.Errorf("invalid cipher suite: %s", v)
		}
		cipherSuites[i] = val
	}

	supportedCurves := make([]utls.CurveID, len(payload.SupportedGroups))
	for i, v := range payload.SupportedGroups {
		val, err := stringToUint16(v)
		if err != nil {
			return nil, fmt.Errorf("invalid supported group: %s", v)
		}
		supportedCurves[i] = utls.CurveID(val)
	}

	supportedSignatureAlgorithms := make([]utls.SignatureScheme, len(payload.SignatureAlgorithms))
	for i, v := range payload.SignatureAlgorithms {
		val, err := stringToUint16(v)
		if err != nil {
			return nil, fmt.Errorf("invalid signature algorithm: %s", v)
		}
		supportedSignatureAlgorithms[i] = utls.SignatureScheme(val)
	}

	protocolVersion, err := stringToUint16(payload.ProtocolVersion)
	if err != nil {
		return nil, fmt.Errorf("invalid protocol version: %s", payload.ProtocolVersion)
	}

	spec := &utls.ClientHelloSpec{
		CipherSuites: cipherSuites,
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{ServerName: payload.ServerName},
			&utls.SupportedCurvesExtension{
				Curves: supportedCurves,
			},
			&utls.KeyShareExtension{KeyShares: keyShares},
			&utls.SignatureAlgorithmsExtension{
				SupportedSignatureAlgorithms: supportedSignatureAlgorithms,
			},
			&utls.SupportedVersionsExtension{Versions: []uint16{protocolVersion}},
		},
	}

	return spec, nil
}

/**
 * 0xから始まる16進数文字列をuint16に変換する
 * 例: "0x1301" -> 4865
 */
func stringToUint16(s string) (uint16, error) {
	var result uint16
	_, err := fmt.Sscanf(s, "0x%04x", &result)
	if err != nil {
		return 0, err
	}
	return result, nil
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
