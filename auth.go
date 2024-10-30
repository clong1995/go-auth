package auth

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
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
func Check(sign string, body io.Reader, buf *bytes.Buffer) (ak string, err error) {
	tee := io.TeeReader(body, buf)
	a := new(auth)
	if err = json.Decode(tee, a); err != nil {
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

	resign, err := Sign(buf.Bytes(), ak)
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
func Sign(respByte []byte, ak string) (sign string, err error) {
	sk, err := SecretAccess(ak)
	if err != nil {
		log.Println(err)
		return
	}
	respByte = append(respByte, []byte(sk)...)
	sum := md5.Sum(respByte)
	sign = hex.EncodeToString(sum[:])
	return
}

//增值
//自己跟自己比，不要跟别人比
