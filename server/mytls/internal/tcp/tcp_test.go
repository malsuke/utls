package tcp_test

import (
	"testing"

	"github.com/cysec-dev/tls-golang-book/internal/tcp"
)

func TestConn(t *testing.T) {
	t.Run("example.comへtcp接続を行う", func(t *testing.T) {
		conn, err := tcp.Conn("localhost", 443)
		if err != nil {
			t.Fatalf("failed to connect: %v", err)
		}
		if conn == nil {
			t.Fatalf("connection is nil")
		}
		defer conn.Close()
	})
}
