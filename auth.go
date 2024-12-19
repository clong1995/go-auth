package auth

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"github.com/clong1995/go-encipher/json"
	"log"
	"time"
)

type auth struct {
	AccessKeyID string `json:"a"`
	Timestamp   int64  `json:"t"`
}

// Check 解码auth
func Check(sign string, req []byte) (ak string, err error) {
	a := new(auth)
	if err = json.Decode(bytes.NewBuffer(req), a); err != nil {
		log.Println(err)
		return
	}
	ts := time.Now().Unix()
	if !(a.Timestamp-60 <= ts && ts <= a.Timestamp+60) {
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

// Sign 签名
func Sign(req []byte, ak string) (sign string, err error) {
	sk, err := SecretAccess(ak)
	if err != nil {
		log.Println(err)
		return
	}
	hash := md5.New()
	hash.Write(append(req, []byte(sk)...))
	md5Sum := hash.Sum(nil)
	sign = hex.EncodeToString(md5Sum)
	return
}

// NoSign 没有签名
func NoSign(req []byte) (sign string, err error) {
	hash := md5.New()
	hash.Write(req)
	md5Sum := hash.Sum(nil)
	sign = hex.EncodeToString(md5Sum)
	return
}
