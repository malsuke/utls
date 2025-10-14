package tcp

import (
	"fmt"
	"log/slog"
	"net"
	"strconv"
)

func Conn(host string, port int) (*net.TCPConn, error) {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	serverTcpAddr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve address: %w", err)
	}

	conn, err := net.DialTCP("tcp", nil, serverTcpAddr)
	if err != nil {
		slog.Error("Failed to connect to server", "host", host, "port", port, "error", err)
		return nil, err
	}
	return conn, nil
}
