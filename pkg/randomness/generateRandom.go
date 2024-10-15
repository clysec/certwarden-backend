package randomness

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

func RandomHexBytes(count int) (string, error) {
	buf := make([]byte, count)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		return "", fmt.Errorf("could not generate %d random bytes: %v", count, err)
	}

	return hex.EncodeToString(buf), nil
}
