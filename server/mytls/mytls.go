package mytls

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"github.com/refraction-networking/utls/server/mytls/internal/common"
	"github.com/refraction-networking/utls/server/mytls/internal/handshake"
	"github.com/refraction-networking/utls/server/mytls/internal/handshake/extensions"
	"github.com/refraction-networking/utls/server/mytls/internal/record"
	"github.com/refraction-networking/utls/server/mytls/internal/tcp"
	"github.com/refraction-networking/utls/server/openapi"
)

func GenEcdhX25519() (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pub := priv.PublicKey()
	return priv, pub, nil
}

// PerformHandshake は、指定されたTLSパラメータを使用して独自のTLS実装でハンドシェイクを実行し、
// サーバーからの生の応答バイト列を返します。
func PerformHandshake(params openapi.TlsClientParameters) ([]byte, []byte, error) {
	fmt.Println("PerformHandshake called with params:", params.ServerName)
	conn, err := tcp.Conn(params.ServerName, 443) // ポートは443で固定
	if err != nil {
		return nil, nil, fmt.Errorf("tcp.Conn error: %w", err)
	}
	defer conn.Close()

	// TODO: paramsのKeySharesに基づいて鍵を生成する
	_, pub, err := GenEcdhX25519()
	if err != nil {
		return nil, nil, fmt.Errorf("GenEcdhX25519 error: %w", err)
	}

	// TODO: paramsの他のパラメータ（CipherSuitesなど）をExtensionに変換する
	exts := []extensions.Extension{
		*extensions.NewServerNameExtension(params.ServerName),
		*extensions.NewSupportedVersionsExtension(),
		*extensions.NewPskKeyExchangeModesExtension(),
		*extensions.NewSignatureAlgorithmsExtension(),
		*extensions.NewSupportedGroupsExtension(),
		*extensions.NewKeyShareExtension(pub.Bytes()),
	}

	client, err := handshake.NewClientHello(exts)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake.NewClientHello error: %w", err)
	}

	// TODO: params.ClientRandom をclient.Randomに設定する

	clientHandshake := handshake.NewHandshake(common.ClientHello, client.Marshal())
	clientRecord, err := record.NewTLSRecord(common.Handshake, clientHandshake.Marshal())
	if err != nil {
		return nil, nil, fmt.Errorf("record.NewTLSRecord error: %w", err)
	}

	sentBytes := clientRecord.Marshal()
	_, err = conn.Write(sentBytes)
	if err != nil {
		return sentBytes, nil, fmt.Errorf("conn.Write error: %w", err)
	}

	buffer := make([]byte, 8192)
	n, err := conn.Read(buffer)
	if err != nil {
		return sentBytes, nil, fmt.Errorf("conn.Read error: %w", err)
	}

	return sentBytes, buffer[:n], nil
}
