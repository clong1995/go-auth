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
func Check(sign string, body io.Reader, buf *bytes.Buffer) (id uint64, err error) {
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

	id, sk, err := SecretAccess(a.AccessKeyID)
	if err != nil {
		log.Println(err)
		return
	}

	if sign != Sign(buf.Bytes(), sk) {
		err = fmt.Errorf("数据签名检验失败")
		log.Println(err)
		return
	}

	return
}

// Sign 签名
func Sign(respByte []byte, sk string) string {
	respByte = append(respByte, []byte(sk)...)
	sum := md5.Sum(respByte)
	return hex.EncodeToString(sum[:])
}

//增值
//自己跟自己比，不要跟别人比
