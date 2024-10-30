package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"time"
)

// SecretAccess 编码sk
func SecretAccess(ak string) (secretAccessKey string, err error) {
	id, session, err := ID(ak)
	if err != nil {
		log.Println(err)
		return
	}

	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, (session+id)*2)
	secretAccessKey = encodeB64(b)
	return
}

// AccessID 编码ak
func AccessID(id uint64) string {
	//加入时间戳
	session := uint64(time.Now().UnixNano())
	tsBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(tsBytes, session)

	//加入id
	idBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(idBytes, id+session)

	//合并
	tsBytes = append(tsBytes, idBytes...)

	//返回string
	return base64.RawURLEncoding.EncodeToString(tsBytes)
}

// ID 获取id
func ID(ak string) (id, session uint64, err error) {
	bs, err := decodeB64(ak)
	if err != nil {
		log.Println(err)
		return
	}

	buff := bytes.NewBuffer(bs)
	b := make([]byte, 8)

	//提取时间戳
	if _, err = buff.Read(b); err != nil {
		log.Println(err)
		return
	}
	session = binary.LittleEndian.Uint64(b)

	//提取id
	if _, err = buff.Read(b); err != nil {
		log.Println(err)
		return
	}
	id = binary.LittleEndian.Uint64(b) - session

	return
}

// base64 加密byte[]为string，可用于url
func encodeB64(bytes []byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes)
}

// 解密base64的string为byte[]
func decodeB64(str string) (bytes []byte, err error) {
	if str == "" {
		err = fmt.Errorf("base64Str is empty")
		log.Println(err)
		return
	}
	if bytes, err = base64.RawURLEncoding.DecodeString(str); err != nil {
		log.Println(err)
		return
	}
	return
}
