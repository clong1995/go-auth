package auth

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"math"
	"time"

	"github.com/pkg/errors"
)

// Check 用于校验API请求的签名和时间戳。
// 它首先从请求体中解析出 AccessKeyID 和时间戳，然后进行以下检查：
// 1. 检查 AccessKeyID 是否存在。
// 2. 校验请求时间戳是否在允许的时间窗口内（当前时间 ± out 秒）。
// 3. 使用相同的 AccessKeyID 重新计算签名，并与传入的签名进行比对。
//
// sign: 客户端计算并传入的请求签名字符串。
// out: 允许的时间误差，单位为秒。请求时间戳与服务器当前时间的差值如果超过这个值，则请求无效。
// req: 原始的HTTP请求体 []byte。
//
// 返回值: 如果校验成功，返回 AccessKeyID 和 nil；否则返回空字符串和相应的错误信息。
func Check(sign string, out int64, req []byte, path string) (string, error) {
	// preData 用于从请求体JSON中解析出 AccessKeyID 和时间戳。
	type preData struct {
		AccessKeyID string `json:"a"` // "a" 对应JSON中的 AccessKeyID 字段
		Timestamp   int64  `json:"t"` // "t" 对应JSON中的时间戳字段
	}

	// 解析请求体
	pData := new(preData)
	if err := json.Unmarshal(req, pData); err != nil {
		return "", errors.WithStack(err)
	}
	if pData.AccessKeyID == "" {
		return "", errors.New("missing access key id")
	}

	// 校验时间戳
	ts := time.Now().Unix()
	if math.Abs(float64(ts-pData.Timestamp)) > float64(out) {
		return "", errors.New("时间已过期")
	}
	ak := pData.AccessKeyID

	// 重新计算签名以进行校验
	resign, err := Sign(req, ak, path)
	if err != nil {
		return "", err
	}

	// 对比客户端签名和服务端计算的签名
	if resign != sign {
		return "", errors.New("数据签名检验失败")
	}

	return ak, nil
}

// Sign 使用 AccessKey (ak) 获取对应的 SecretKey (sk)，然后对请求体进行签名。
// 签名算法为：md5(请求体 + SecretKey)。
//
// req: 原始的HTTP请求体 []byte。
// ak:  用户的 AccessKeyID。
//
// 返回值: 返回计算出的签名字符串和nil；如果过程出错，则返回空字符串和错误信息。
func Sign(req []byte, ak, path string) (string, error) {
	if ak == "" {
		return "", errors.New("secret access key is empty")
	}
	// 通过 AccessKey 获取对应的 SecretKey
	sk, err := SecretAccess(ak)
	if err != nil {
		return "", err
	}
	// 计算签名
	hash := md5.New()
	req = append(req, path...)
	hash.Write(append(req, sk...))
	md5Sum := hash.Sum(nil)
	return hex.EncodeToString(md5Sum), nil
}
