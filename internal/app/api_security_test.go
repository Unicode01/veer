package app

import "testing"

func TestAPIBindExposesRemoteClients(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
		want bool
	}{
		{name: "nil config", cfg: nil, want: false},
		{name: "default bind", cfg: &Config{}, want: false},
		{name: "ipv4 loopback", cfg: &Config{WebBind: "127.0.0.1"}, want: false},
		{name: "ipv6 loopback", cfg: &Config{WebBind: "::1"}, want: false},
		{name: "localhost", cfg: &Config{WebBind: "localhost"}, want: false},
		{name: "all ipv4", cfg: &Config{WebBind: "0.0.0.0"}, want: true},
		{name: "all ipv6", cfg: &Config{WebBind: "::"}, want: true},
		{name: "specific remote ip", cfg: &Config{WebBind: "192.0.2.10"}, want: true},
		{name: "hostname", cfg: &Config{WebBind: "example.com"}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := apiBindExposesRemoteClients(tt.cfg); got != tt.want {
				t.Fatalf("apiBindExposesRemoteClients() = %v, want %v", got, tt.want)
			}
		})
	}
}
