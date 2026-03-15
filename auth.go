package auth

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"math"
	"time"

	"github.com/pkg/errors"
)

// Check 提取数据中用户ak,校验数据签名
func Check(sign string, out int64, req []byte) (string, error) {
	type preData struct {
		AccessKeyID string `json:"a"`
		Timestamp   int64  `json:"t"`
	}

	pData := new(preData)
	if err := json.Unmarshal(req, pData); err != nil {
		return "", errors.Wrap(err, "请求体解码失败")
	}
	if pData.AccessKeyID == "" {
		return "", errors.New("missing access key id")
	}

	ts := time.Now().Unix()
	if math.Abs(float64(ts-pData.Timestamp)) > float64(out) {
		return "", errors.New("时间已过期")
	}
	ak := pData.AccessKeyID

	resign, err := Sign(req, ak)
	if err != nil {
		return "", errors.Wrap(err, "生成签名失败")
	}

	if resign != sign {
		return "", errors.New("数据签名检验失败")
	}

	return ak, nil
}

// Sign 通过ak提取sk进行数据签名
func Sign(req []byte, ak string) (string, error) {
	if ak == "" {
		return "", errors.New("secret access key is empty")
	}
	sk, err := SecretAccess(ak)
	if err != nil {
		return "", errors.Wrap(err, "获取 secret key 失败")
	}
	hash := md5.New()
	hash.Write(append(req, sk...))
	md5Sum := hash.Sum(nil)
	return hex.EncodeToString(md5Sum), nil
}
