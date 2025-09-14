package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"
)

func main() {
	targetURL := "www.example.com"
	targetPort := "443"

	// 1. X25519で秘密鍵と公開鍵を作成
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
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
			&utls.SupportedCurvesExtension{
				Curves: []utls.CurveID{utls.X25519, utls.CurveP256, utls.CurveP384},
			},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.X25519, Data: publicKey.Bytes()},
				{Group: utls.CurveP256},
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0}}, // uncompressed
			&utls.SignatureAlgorithmsExtension{
				SupportedSignatureAlgorithms: []utls.SignatureScheme{
					utls.ECDSAWithP256AndSHA256,
					utls.PSSWithSHA256,
					utls.PKCS1WithSHA256,
				},
			},
		},
	}

	// 2. TCP接続
	conn, err := net.DialTimeout("tcp", targetURL+":"+targetPort, 5*time.Second)
	if err != nil {
		fmt.Printf("net.Dial error: %v\n", err)
		return
	}
	defer conn.Close()

	// 3. uTLSでUConnを作成し、specを適用
	config := &utls.Config{ServerName: targetURL}
	uconn := utls.UClient(conn, config, utls.HelloCustom)
	if err := uconn.ApplyPreset(&spec); err != nil {
		fmt.Printf("ApplyPreset error: %v\n", err)
		return
	}

	// 4. ハンドシェイクの前に、使用する秘密鍵を設定する
	// (カスタムspecを使う場合、この方法がよりシンプルで確実です)
	if uconn.HandshakeState.State13.KeyShareKeys != nil {
		uconn.HandshakeState.State13.KeyShareKeys.Ecdhe = privateKey
		fmt.Println("✅ In-memory private key set for handshake.")
	} else {
		fmt.Println("Error: HandshakeState is not properly initialized after ApplyPreset.")
		return
	}

	// 5. TLSハンドシェイクを実行
	err = uconn.Handshake()
	if err != nil {
		fmt.Printf("uconn.Handshake() error: %v\n", err)
		return
	}
	fmt.Println("✅ TLS Handshake successful")

	// [変更点 2] http2.Transportをhttp.Transportに変更
	tr := &http.Transport{
		// [変更点 3] DialTLSの代わりにDialTLSContextを使用
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// ハンドシェイク済みのuconnを返す
			return uconn, nil
		},
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
	}

	// 6. GETリクエスト
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "https://"+targetURL+"/", nil)
	req.Header.Set("User-Agent", "custom-utls-client")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("HTTP/1.1 request error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// 応答ヘッダーで "HTTP/1.1" が使われていることを確認
	fmt.Printf("📬 HTTPステータス: %s (%s)\n", resp.Status, resp.Proto)
	fmt.Println("--- Response Headers ---")
	for k, v := range resp.Header {
		fmt.Printf("%s: %s\n", k, v)
	}
	fmt.Println("------------------------")

	body, _ := io.ReadAll(resp.Body)
	fmt.Println("\n--- レスポンス内容 ---")
	fmt.Println(string(body))
}
