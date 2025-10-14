package crypto

import (
	"crypto/rand"
	"fmt"
	"io"
)

func GenerateRandom32Bytes() ([32]byte, error) {
	var array [32]byte
	_, err := io.ReadFull(rand.Reader, array[:])
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return array, nil
}
