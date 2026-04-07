package auth

import (
	"encoding/binary"

	"github.com/pkg/errors"
)

// SecretAccess 是一个高级函数，通过 AccessKey (ak) 获取对应的 SecretKey (sk)。
// 它的内部流程是：先通过 ID() 函数从 ak 中解码出原始的 id 和 session，
// 然后调用 secretAccess() 函数来生成 sk。
//
// ak: 用户的 AccessKey 字符串。
//
// 返回值: 返回生成的 SecretKey 字符串和nil；如果出错则返回空字符串和错误。
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

// AccessID 用于将用户ID (id) 和会话标识 (session) 编码成一个 AccessKey (ak)。
// 编码规则：
// 1. 创建一个16字节的切片。
// 2. 前8字节存放 session 的小端序。
// 3. 后8字节存放 (id + session) 的小端序。
// 4. 对整个16字节切片进行自定义的B64编码。
//
// id: 用户ID。
// session: 会话或随机标识。
//
// 返回值: 返回编码后的 AccessKey 字符串和nil；如果id为0则返回错误。
func AccessID(id, session int64) (string, error) {
	if id == 0 {
		return "", errors.New("access id is empty")
	}

	tsBytes := make([]byte, 16)
	binary.LittleEndian.PutUint64(tsBytes[:8], uint64(session))
	binary.LittleEndian.PutUint64(tsBytes[8:], uint64(id+session))

	return encodeB64(tsBytes), nil
}

// ID 是 AccessID 的逆向操作，用于从 AccessKey (ak) 中解码出原始的 id 和 session。
// 解码规则：
// 1. 对 ak 字符串进行自定义的B64解码，得到16字节的切片。
// 2. 从前8字节解析出 session。
// 3. 从后8字节解析出 (id + session) 的值。
// 4. 通过 (id + session) - session 计算出原始的 id。
//
// ak: AccessKey 字符串。
//
// 返回值: 返回解码出的 id, session 和 nil；如果解码失败或ak无效，则返回0, 0和错误。
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
	idEncoded := int64(binary.LittleEndian.Uint64(bs[8:16]))

	id := idEncoded - session

	return id, session, nil
}

func Auth(id, session int64) (string, string, error) {
	ak, err := AccessID(id, session)
	if err != nil {
		return "", "", err
	}
	sk := secretAccess(id, session)
	return ak, sk, nil
}

// secretAccess 是一个内部函数，用于根据 id 和 session 生成最终的 SecretKey (sk)。
// 生成规则：
// 1. 计算 i = (session + id) * 2。
// 2. 将 i 转换为8字节的小端序切片。
// 3. 对该切片进行自定义的B64编码，得到最终的 sk。
func secretAccess(id int64, session int64) string {
	i := (session + id) * 2
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(i))
	return encodeB64(b)
}
