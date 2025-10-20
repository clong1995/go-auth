package auth

import (
	"encoding/binary"
	"errors"
	"log"
)

// SecretAccess 通过ak编码sk
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
	secretAccessKey = secretAccess(id, session)
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

	ak = encodeB64(tsBytes)
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

// 编码sk
func secretAccess(id int64, session int64) (key string) {
	i := (session + id) * 2
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(i))
	key = encodeB64(b)
	return
}
