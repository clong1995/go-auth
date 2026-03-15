package auth

import (
	"encoding/binary"

	"github.com/pkg/errors"
)

// SecretAccess 通过ak编码sk
func SecretAccess(ak string) (string, error) {
	if ak == "" {
		return "", errors.New("secret access key is empty")
	}
	id, session, err := ID(ak)
	if err != nil {
		return "", errors.Wrap(err, "get secret access key failed")
	}
	return secretAccess(id, session), nil
}

// AccessID 编码ak
func AccessID(id, session int64) (string, error) {
	if id == 0 {
		return "", errors.New("access id is empty")
	}

	tsBytes := make([]byte, 16)
	binary.LittleEndian.PutUint64(tsBytes[:8], uint64(session))
	binary.LittleEndian.PutUint64(tsBytes[8:], uint64(id+session))

	return encodeB64(tsBytes), nil
}

// ID 获取id
func ID(ak string) (int64, int64, error) {
	if ak == "" {
		return 0, 0, errors.New("secret access key is empty")
	}
	bs, err := decodeB64(ak)
	if err != nil {
		return 0, 0, errors.Wrap(err, "decode secret access key failed")
	}

	if len(bs) < 16 {
		return 0, 0, errors.Wrap(err, "invalid access key length")
	}

	session := int64(binary.LittleEndian.Uint64(bs[:8]))
	id := int64(binary.LittleEndian.Uint64(bs[8:16]))

	id -= session

	return id, session, nil
}

// 编码sk
func secretAccess(id int64, session int64) string {
	i := (session + id) * 2
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(i))
	return encodeB64(b)
}
