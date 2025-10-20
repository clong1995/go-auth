package auth

import (
	"encoding/base64"
	"log"

	"github.com/clong1995/go-config"
)

var authKey []byte
var authKeyLen int

func init() {
	key := config.Value("AUTH KEY")
	if key != "" {
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
func decodeB64(str string) (bytes []byte, err error) {
	bytes, err = base64.RawURLEncoding.DecodeString(str)
	xor(bytes)
	if err != nil {
		log.Println(err)
		return
	}
	return
}
