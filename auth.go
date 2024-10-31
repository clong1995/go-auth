package auth

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"github.com/clong1995/go-encipher/json"
	"io"
	"log"
	"time"
)

type auth struct {
	AccessKeyID string `json:"a"`
	Timestamp   int64  `json:"t"`
}

// Check 解码auth
func Check(sign string, reader io.Reader) (ak string, err error) {
	a := new(auth)
	var buf *bytes.Buffer
	if err = json.Decode(io.TeeReader(reader, buf), a); err != nil {
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

	resign, err := Sign(buf, ak)
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
func Sign(reader io.Reader, ak string) (sign string, err error) {
	sk, err := SecretAccess(ak)
	if err != nil {
		log.Println(err)
		return
	}
	hash := md5.New()
	_, err = io.Copy(hash, reader)
	if err != nil {
		log.Println(err)
		return
	}
	md5Sum := hash.Sum([]byte(sk))
	sign = fmt.Sprintf("%x", md5Sum)
	return
}

//增值
//自己跟自己比，不要跟别人比
