package brokercore

import "testing"

// UsesDNSRemotely tells the operator-facing observability surface whether the
// proxy (rather than the broker) resolves the target hostname. It matters
// because local network-policy validation cannot see the address a remotely-
// resolving proxy will actually reach, so those schemes must be treated as
// advisory rather than a hard SSRF boundary.
//
// socks5h, and http/https (CONNECT sends the hostname to the proxy) all
// resolve remotely; plain socks5 resolves locally and hands over an IP.
func TestUsesDNSRemotelyPerScheme(t *testing.T) {
	cases := []struct {
		scheme string
		want   bool
	}{
		{UpstreamProxySchemeHTTP, true},
		{UpstreamProxySchemeHTTPS, true},
		{UpstreamProxySchemeSOCKS5, false},
		{UpstreamProxySchemeSOCKS5H, true},
		{"", false},
		{"ftp", false},
	}
	for _, tc := range cases {
		p := &UpstreamProxy{Name: "p", Scheme: tc.scheme, Host: "proxy:3128"}
		if got := p.UsesDNSRemotely(); got != tc.want {
			t.Errorf("UsesDNSRemotely(scheme=%q) = %v, want %v", tc.scheme, got, tc.want)
		}
	}
	if (*UpstreamProxy)(nil).UsesDNSRemotely() {
		t.Fatal("nil profile must not report remote DNS resolution")
	}
}
