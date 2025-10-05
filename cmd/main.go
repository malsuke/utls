package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	tls "github.com/refraction-networking/utls"
	utls "github.com/refraction-networking/utls"
)

func main() {
	var serverResponse []byte
	targetURL := "www.example.com"
	targetPort := "443"

	// 1. 鍵ペアの作成 (変更なし)
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	fmt.Println(hex.Dump(privateKey.PublicKey().Bytes()))
	if err != nil {
		fmt.Printf("Failed to generate X25519 key pair: %v\n", err)
		return
	}
	publicKey := privateKey.PublicKey()
	fmt.Println("✅ X25519 key pair generated in main.go.")

	spec := utls.ClientHelloSpec{
		CipherSuites: []uint16{
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{ServerName: targetURL},
			&utls.SupportedCurvesExtension{ // supported_groupsと同じ
				Curves: []utls.CurveID{utls.X25519, utls.CurveP256, utls.CurveP384},
			},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.X25519, Data: publicKey.Bytes()},
				{Group: utls.CurveP256},
			}},
			&utls.SignatureAlgorithmsExtension{
				SupportedSignatureAlgorithms: []utls.SignatureScheme{
					utls.ECDSAWithP256AndSHA256,
					utls.PSSWithSHA256,
					utls.PKCS1WithSHA256,
				},
			},
			&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13}},
		},
	}

	// 3. TCP接続とTLSハンドシェイク (変更なし)
	conn, err := net.DialTimeout("tcp", targetURL+":"+targetPort, 5*time.Second)
	if err != nil {
		fmt.Printf("net.Dial error: %v\n", err)
		return
	}
	defer conn.Close()

	config := &utls.Config{
		ServerName:     targetURL,
		ServerResponse: &serverResponse,
		KeyLogWriter:   os.Stderr,
		MinVersion:     utls.VersionTLS13,
		MaxVersion:     utls.VersionTLS13,
	}
	uconn := utls.UClient(conn, config, utls.HelloCustom)
	if err := uconn.ApplyPreset(&spec); err != nil {
		fmt.Printf("ApplyPreset error: %v\n", err)
		return
	}

	myRandom := []byte{
		0x5b,
	}

	if err := uconn.SetClientRandom(myRandom); err != nil {
		fmt.Printf("SetClientRandom error: %v\n", err)
		return
	}

	if uconn.HandshakeState.State13.KeyShareKeys != nil {
		uconn.HandshakeState.State13.KeyShareKeys.Ecdhe = privateKey
		fmt.Println("✅ In-memory private key set for handshake.")
	} else {
		fmt.Println("Error: HandshakeState is not properly initialized after ApplyPreset.")
		return
	}

	if err := uconn.Handshake(); err != nil {
		fmt.Printf("uconn.Handshake() error: %v\n", err)
		if serverResponse != nil {
			fmt.Println("--- ServerResponse bytes on error ---")
			fmt.Print(hex.Dump(serverResponse))
			fmt.Println("-------------------------------------")
		}
		return
	}

	fmt.Print(hex.Dump(tls.ClientHelloRaw))
	fmt.Println("✅ TLS Handshake successful")

	if serverResponse != nil {
		fmt.Println("--- ServerResponse bytes ---")
		fmt.Print(hex.Dump(serverResponse))
		fmt.Println("--------------------------")
	}

	requestBuilder := &strings.Builder{}
	requestBuilder.WriteString("GET / HTTP/1.1\r\n")
	requestBuilder.WriteString("Host: " + targetURL + "\r\n")
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
		return
	}

	response, err := io.ReadAll(uconn)
	if err != nil {
		fmt.Printf("io.ReadAll(uconn) error: %v\n", err)
		return
	}

	fmt.Println("\n--- Raw Response ---")
	fmt.Println(string(response))
	fmt.Println("--------------------")
}
