package auth

import (
	"encoding/base64"

	"github.com/clong1995/go-config"
	"github.com/pkg/errors"
)

var authKey []byte
var authKeyLen int

func init() {
	if key, exists := config.Value("AUTH KEY"); exists && key != "" {
		authKey = []byte(key)
		authKeyLen = len(authKey)
	}
}

func xor(data []byte) {
	if authKeyLen == 0 {
		return
	}
	for i := 0; i < len(data); i++ {
		data[i] = data[i] ^ authKey[i%authKeyLen]
	}
	return
}

// base64 加密byte[]为string，可用于url
func encodeB64(bytes []byte) string {
	xor(bytes)
	return base64.RawURLEncoding.EncodeToString(bytes)
}

// 解密base64的string为byte[]
func decodeB64(str string) ([]byte, error) {
	bytes, err := base64.RawURLEncoding.DecodeString(str)
	xor(bytes)
	if err != nil {
		return nil, errors.Wrap(err, "")
	}
	return bytes, nil
}
