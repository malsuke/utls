package handler

import (
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
	uconn := utls.UClient(conn, config, utls.HelloCustom)
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
	}

	// raw_server_application_data_response はuTLSから直接取得できないため空にする
	rawServerApplicationDataResponse := ""

	appResponse := openapi.ApplicationResponse{
		RawClientHello:                          hex.EncodeToString(convertRecordbytes(utls.ClientHelloRaw)),
		RawServerResponse:                       hex.EncodeToString(serverResponse),
		RawServerResponseDecoded:                hex.EncodeToString(utls.FullRecordBytes),
		RawServerApplicationDataResponse:        rawServerApplicationDataResponse,
		RawServerApplicationDataResponseDecoded: hex.EncodeToString(httpResponse),
	}

	return ctx.JSON(200, appResponse)
}
