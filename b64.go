package auth

import (
	"encoding/base64"

	"github.com/pkg/errors"
)

// xor 函数对传入的字节切片进行原地XOR（异或）操作。
// 它使用 init 函数中加载的 authKey 作为密钥。
// 这是一个简单的对称加密/混淆方法，密钥的每个字节会与数据循环异或。
func xor(data []byte) {
	if configAuthKey == "" {
		return
	}
	for i := 0; i < len(data); i++ {
		data[i] = data[i] ^ configAuthKey[i%len(configAuthKey)]
	}
	return
}

// encodeB64 是一个自定义的编码函数。
// 它首先对原始字节数据进行XOR操作，然后再进行URL安全的Base64编码。
//
// bytes: 待编码的原始字节切片。
//
// 返回值: 返回经过XOR和Base64编码后的字符串。
func encodeB64(bytes []byte) string {
	xor(bytes) // 先进行XOR操作
	return base64.RawURLEncoding.EncodeToString(bytes)
}

// decodeB64 是 encodeB64 的逆向操作。
// 它首先对输入的Base64字符串进行解码，然后再对解码后的数据进行XOR操作以还原原始数据。
//
// str: 待解码的字符串。
//
// 返回值: 返回还原后的原始字节切片和nil；如果Base64解码失败则返回错误。
func decodeB64(str string) ([]byte, error) {
	bytes, err := base64.RawURLEncoding.DecodeString(str)
	if err != nil {
		// 注意：如果解码失败，不应该继续执行XOR操作。
		return nil, errors.Wrap(err, "base64解码失败")
	}
	xor(bytes) // Base64解码成功后，再进行XOR操作
	return bytes, nil
}
