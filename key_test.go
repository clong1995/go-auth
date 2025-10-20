package auth

import (
	"testing"
)

func TestID(t *testing.T) {
	type args struct {
		ak string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "获取id",
			args: args{ak: "bFRqZflzZXRqWODUvwQ7dg"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotId, gotSession, err := ID(tt.args.ak)
			if (err != nil) != tt.wantErr {
				t.Errorf("ID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			t.Logf("ID() gotId = %v,gotSession = %v", gotId, gotSession)
		})
	}
}

func TestAccessID(t *testing.T) {
	type args struct {
		id      int64
		session int64
	}
	tests := []struct {
		name    string
		args    args
		wantAk  string
		wantErr bool
	}{
		{
			name: "test AccessID",
			args: args{
				id:      1539798057070104576,
				session: 1760938241281,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAk, err := AccessID(tt.args.id, tt.args.session)
			if (err != nil) != tt.wantErr {
				t.Errorf("AccessID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			t.Logf("AccessID() gotAk = %v", gotAk)
		})
	}
}
