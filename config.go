package auth

import "github.com/clong1995/go-config"

var configAuthKey string

func init() {
	configAuthKey, _ = config.Value[string]("AUTH KEY")
}
