package auth

import "testing"

func TestSign(t *testing.T) {
	type args struct {
		bytes []byte
		ak    string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Sign 签名",
			args: args{
				bytes: []byte("hello world"),
				ak:    "2Uig57wlBgDmSKD4mw1kBw",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSign, err := Sign(tt.args.bytes, tt.args.ak)
			if (err != nil) != tt.wantErr {
				t.Errorf("Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			t.Logf("Sign() gotSign = %v", gotSign)
		})
	}
}

func TestCheck(t *testing.T) {
	type args struct {
		sign string
		req  []byte
	}
	tests := []struct {
		name    string
		args    args
		wantAk  string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			/*gotAk, err := Check(tt.args.sign, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("Check() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotAk != tt.wantAk {
				t.Errorf("Check() gotAk = %v, want %v", gotAk, tt.wantAk)
			}*/
		})
	}
}
