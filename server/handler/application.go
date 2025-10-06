package handler

import (
	"encoding/hex"
	"encoding/json"
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

func (s Server) PostTlsApplication(ctx echo.Context) error {
	var payload openapi.HandshakeRequest
	if err := ctx.Bind(&payload); err != nil {
		return ctx.JSON(400, "Invalid payload")
	}

	var serverResponse []byte
	conn, err := net.DialTimeout("tcp", payload.Server+":"+fmt.Sprintf("%d", *payload.Port), 5*time.Second)
	if err != nil {
		return ctx.JSON(500, fmt.Sprintf("net.Dial error: %v", err))
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
		return ctx.JSON(500, fmt.Sprintf("ApplyPreset error: %v", err))
	}

	if err := uconn.SetClientRandom([]byte(payload.ClientRandom)); err != nil {
		return ctx.JSON(500, fmt.Sprintf("SetClientRandom error: %v", err))
	}

	if err := uconn.Handshake(); err != nil {
		return ctx.JSON(500, fmt.Sprintf("uconn.Handshake() error: %v", err))
	}

	// fmt.Println(hex.Dump(utls.FullRecordBytes))

	responseBytes, err := json.Marshal(openapi.HandshakeResponse{
		HandshakeSuccess:         true,
		RawClientHello:           hex.EncodeToString(convertRecordbytes(utls.ClientHelloRaw)),
		RawServerResponse:        hex.EncodeToString(serverResponse),
		RawServerResponseDecoded: hex.EncodeToString(utls.FullRecordBytes),
	})
	if err != nil {
		return ctx.JSON(500, fmt.Sprintf("json.Marshal error: %v", err))
	}

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

	return ctx.JSON(200, json.RawMessage(responseBytes))

}
