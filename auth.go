package auth

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/clong1995/go-encipher/json"
)

type auth struct {
	AccessKeyID string `json:"a"`
	Timestamp   int64  `json:"t"`
}

// Check 提取数据中用户ak,校验数据签名
func Check(sign string, out int, req []byte) (ak string, err error) {
	a := new(auth)
	if err = json.Decode(bytes.NewBuffer(req), a); err != nil {
		log.Println(err)
		return
	}
	if a.AccessKeyID == "" {
		err = errors.New("missing access key id")
		log.Println(err)
		return
	}

	ts := time.Now().Unix()
	o := int64(out)
	if !(a.Timestamp-o <= ts && ts <= a.Timestamp+o) {
		err = fmt.Errorf("时间已过期")
		log.Println(err)
		return
	}
	ak = a.AccessKeyID

	resign, err := Sign(req, ak)
	if err != nil {
		log.Println(err)
		return
	}

	if resign != sign {
		err = fmt.Errorf("数据签名检验失败")
		log.Println(err)
		return
	}

	return
}

// Sign 通过ak提取sk进行数据签名
func Sign(req []byte, ak string) (sign string, err error) {
	if ak == "" {
		err = errors.New("secret access key is empty")
		log.Println(err)
		return
	}
	var sk string
	if sk, err = SecretAccess(ak); err != nil {
		log.Println(err)
		return
	}
	hash := md5.New()
	hash.Write(append(req, sk...))
	md5Sum := hash.Sum(nil)
	sign = hex.EncodeToString(md5Sum)
	return
}
