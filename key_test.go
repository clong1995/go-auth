package auth

import "testing"

func TestAccessID(t *testing.T) {
	type args struct {
		id      int64
		session int64
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "编码ak",
			args: args{
				id:      530835276348522509,
				session: 530835276348522509,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session, ak := AccessID(tt.args.id, tt.args.session)
			t.Logf("AccessID() = %v,%v", session, ak)
		})
	}
}

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
			args: args{ak: "2Uig57wlBgDmSKD4mw1kBw"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotId, gotSession, err := ID(tt.args.ak)
			if (err != nil) != tt.wantErr {
				t.Errorf("ID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			t.Logf("ID() gotId = %v", gotId)
			t.Logf("ID() gotSession = %v", gotSession)
		})
	}
}
