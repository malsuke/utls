package mytls

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/refraction-networking/utls/server/mytls/internal/handshake"
	handshake2 "github.com/refraction-networking/utls/server/mytls/internal/handshake"

	"github.com/refraction-networking/utls/server/mytls/internal/common"
	"github.com/refraction-networking/utls/server/mytls/internal/handshake/extensions"
	"github.com/refraction-networking/utls/server/mytls/internal/record"
	"github.com/refraction-networking/utls/server/mytls/internal/tcp"
	"github.com/refraction-networking/utls/server/openapi"
)

// stringToUint16 は "0x..." 形式の16進数文字列をuint16に変換します。
func stringToUint16(s string) (uint16, error) {
	var result uint16
	_, err := fmt.Sscanf(s, "0x%04x", &result)
	if err != nil {
		return 0, err
	}
	return result, nil
}

// stringsToUint16 は文字列のスライスをuint16のスライスに変換します。
func stringsToUint16(ss []string) ([]uint16, error) {
	results := make([]uint16, len(ss))
	for i, s := range ss {
		val, err := stringToUint16(s)
		if err != nil {
			return nil, fmt.Errorf("invalid hex string '%s': %w", s, err)
		}
		results[i] = val
	}
	return results, nil
}

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
	conn, err := tcp.Conn(params.ServerName, 443) // ポートは443で固定
	if err != nil {
		return nil, nil, fmt.Errorf("tcp.Conn error: %w", err)
	}
	defer conn.Close()

	// SupportedGroups
	supportedGroups, err := stringsToUint16(params.SupportedGroups)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse SupportedGroups: %w", err)
	}

	// SignatureAlgorithms
	sigAlgs, err := stringsToUint16(params.SignatureAlgorithms)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse SignatureAlgorithms: %w", err)
	}

	// KeyShare
	keyShareEntries := []extensions.KeyShareEntry{}
	// すべてのグループで使いまわすためのダミー鍵を一度だけ生成
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate dummy key for KeyShare: %w", err)
	}
	pub := priv.PublicKey()

	for _, groupStr := range params.KeyShares {
		group, err := stringToUint16(groupStr)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid key share group: %w", err)
		}
		keyShareEntries = append(keyShareEntries, extensions.KeyShareEntry{
			Group:       group,
			KeyExchange: pub.Bytes(), // すべてのグループで同じ公開鍵を使いまわす
		})
	}

	// SupportedVersions
	var supportedVersion uint16
	if params.ProtocolVersion != "" {
		supportedVersion, err = stringToUint16(params.ProtocolVersion)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse ProtocolVersion: %w", err)
		}
	}

	exts := []extensions.Extension{
		*extensions.NewServerNameExtension(params.ServerName),
		*extensions.NewSupportedVersionsExtension([]uint16{supportedVersion}),
		*extensions.NewSignatureAlgorithmsExtension(sigAlgs),
		*extensions.NewSupportedGroupsExtension(supportedGroups),
	}
	exts = append(exts, *extensions.NewKeyShareExtension(keyShareEntries))

	// --- ClientHello構築 ---
	client, err := handshake2.NewClientHello(exts)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake.NewClientHello error: %w", err)
	}

	// CipherSuites
	cipherSuites, err := stringsToUint16(params.CipherSuites)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CipherSuites: %w", err)
	}
	cipherSuitesConverted := make([]common.CipherSuite, len(cipherSuites))
	for i, cs := range cipherSuites {
		cipherSuitesConverted[i] = common.CipherSuite(cs)
	}
	client.CipherSuites = cipherSuitesConverted

	// ClientRandom
	if params.ClientRandom != "" {
		randomBytes, err := hex.DecodeString(params.ClientRandom)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode ClientRandom: %w", err)
		}
		if len(randomBytes) == 32 {
			copy(client.Random[:], randomBytes)
		}
	}

	// --- ハンドシェイク実行 ---

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
