package auth

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"log"
)

// SecretAccess 编码sk
func SecretAccess(ak string) (secretAccessKey string, err error) {
	if ak == "" {
		err = errors.New("secret access key is empty")
		log.Println(err)
		return
	}
	id, session, err := ID(ak)
	if err != nil {
		log.Println(err)
		return
	}

	encodedValue := (session + id) * 2
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(encodedValue))

	secretAccessKey = encodeB64(b)
	return
}

// AccessID 编码ak
func AccessID(id, session int64) (ak string, err error) {
	if id == 0 {
		err = errors.New("access id is empty")
		log.Println(err)
		return
	}

	tsBytes := make([]byte, 16)
	binary.LittleEndian.PutUint64(tsBytes[:8], uint64(session))
	binary.LittleEndian.PutUint64(tsBytes[8:], uint64(id+session))

	ak = base64.RawURLEncoding.EncodeToString(tsBytes)
	return
}

// ID 获取id
func ID(ak string) (id, session int64, err error) {
	if ak == "" {
		err = errors.New("secret access key is empty")
		log.Println(err)
		return
	}
	bs, err := decodeB64(ak)
	if err != nil {
		log.Println(err)
		return
	}

	if len(bs) < 16 {
		err = errors.New("invalid access key length")
		log.Println(err)
		return
	}

	session = int64(binary.LittleEndian.Uint64(bs[:8]))
	id = int64(binary.LittleEndian.Uint64(bs[8:16]))

	id -= session

	return
}

// base64 加密byte[]为string，可用于url
func encodeB64(bytes []byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes)
}

// 解密base64的string为byte[]
func decodeB64(str string) (bytes []byte, err error) {
	if bytes, err = base64.RawURLEncoding.DecodeString(str); err != nil {
		log.Println(err)
		return
	}
	return
}
