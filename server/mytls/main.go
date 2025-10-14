package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/cysec-dev/tls-golang-book/internal/common"
	"github.com/cysec-dev/tls-golang-book/internal/handshake"
	"github.com/cysec-dev/tls-golang-book/internal/handshake/extensions"
	"github.com/cysec-dev/tls-golang-book/internal/record"
	"github.com/cysec-dev/tls-golang-book/internal/tcp"
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

func main() {

	conn, err := tcp.Conn("www.example.com", 443)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	_, pub, err := GenEcdhX25519()
	if err != nil {
		log.Fatalf("Failed to generate ECDH key pair: %v", err)
	}

	client, err := handshake.NewClientHello([]extensions.Extension{
		*extensions.NewServerNameExtension("www.example.com"),
		*extensions.NewSupportedVersionsExtension(),
		*extensions.NewPskKeyExchangeModesExtension(),
		*extensions.NewSignatureAlgorithmsExtension(),
		*extensions.NewSupportedGroupsExtension(),
		*extensions.NewKeyShareExtension(pub.Bytes()),
	})
	if err != nil {
		panic(err)
	}

	clientHandshake := handshake.NewHandshake(common.ClientHello, client.Marshal())

	clientRecord, err := record.NewTLSRecord(common.Handshake, clientHandshake.Marshal())
	if err != nil {
		panic(err)
	}

	_, err = conn.Write(clientRecord.Marshal())
	if err != nil {
		panic(err)
	}

	fmt.Print(hex.Dump(clientRecord.Marshal()))

	// 7. Read the response
	buffer := make([]byte, 8192)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Fatalf("Failed to read from connection: %v", err)
	}

	fmt.Printf("Received %d bytes\n", n)
	fmt.Print(hex.Dump(buffer[:n]))

	// Parse the response
	respRecord, err := record.ParseRecord(buffer[:n])
	if err != nil {
		log.Fatalf("Failed to parse record: %v", err)
	}

	// The first response should be a handshake record
	if respRecord.Type != common.Handshake {
		log.Fatalf("Expected handshake record, but got %v", respRecord.Type)
	}

	// Parse Handshake
	serverHandshakeData := respRecord.Payload
	if len(serverHandshakeData) < 4 {
		log.Fatalf("Handshake data too short")
	}
	serverHandshakeType := common.HandshakeType(serverHandshakeData[0])
	serverHandshakeLen := int(serverHandshakeData[1])<<16 | int(serverHandshakeData[2])<<8 | int(serverHandshakeData[3])
	serverHandshakeBody := serverHandshakeData[4 : 4+serverHandshakeLen]

	if serverHandshakeType != common.ServerHello {
		log.Fatalf("Expected ServerHello, but got %v", serverHandshakeType)
	}

	// Parse ServerHello
	if len(serverHandshakeBody) < 38 {
		log.Fatalf("ServerHello too short")
	}
	serverHello := &handshake.ServerHello{}
	serverHello.ProtocolVersion = common.TLSVersion(binary.BigEndian.Uint16(serverHandshakeBody[0:2]))
	copy(serverHello.Random[:], serverHandshakeBody[2:34])
	sessionIDLen := int(serverHandshakeBody[34])
	if len(serverHandshakeBody) < 35+sessionIDLen {
		log.Fatalf("ServerHello too short for session ID")
	}
	serverHello.SessionID = serverHandshakeBody[35 : 35+sessionIDLen]
	cipherSuiteOffset := 35 + sessionIDLen
	serverHello.CipherSuite = common.CipherSuite(binary.BigEndian.Uint16(serverHandshakeBody[cipherSuiteOffset : cipherSuiteOffset+2]))
	serverHello.CompressionMethod = serverHandshakeBody[cipherSuiteOffset+2]

	extensionsOffset := cipherSuiteOffset + 3
	if len(serverHandshakeBody) > extensionsOffset {
		extensionsLen := int(binary.BigEndian.Uint16(serverHandshakeBody[extensionsOffset : extensionsOffset+2]))
		extensionsOffset += 2
		if len(serverHandshakeBody) < extensionsOffset+extensionsLen {
			log.Fatalf("ServerHello too short for extensions")
		}
		extensionsData := serverHandshakeBody[extensionsOffset : extensionsOffset+extensionsLen]
		parsedExtensions, err := extensions.UnMarshalExtensions(extensionsData)
		if err != nil {
			log.Fatalf("Failed to parse extensions: %v", err)
		}
		for _, ext := range parsedExtensions {
			serverHello.Extensions = append(serverHello.Extensions, *ext)
		}
	}

	fmt.Printf("\n--- Parsed ServerHello ---\n")
	fmt.Printf("ProtocolVersion: %s\n", serverHello.ProtocolVersion)
	fmt.Printf("Random: %x\n", serverHello.Random)
	fmt.Printf("SessionID: %x\n", serverHello.SessionID)
	fmt.Printf("CipherSuite: %s\n", serverHello.CipherSuite)
	fmt.Printf("CompressionMethod: %d\n", serverHello.CompressionMethod)
	fmt.Printf("Extensions:\n")
	for _, ext := range serverHello.Extensions {
		fmt.Printf("  ExtensionType: %s (0x%04x)\n", ext.Type, ext.Type)
		fmt.Printf("  Payload: %x\n", ext.Payload)
	}
}