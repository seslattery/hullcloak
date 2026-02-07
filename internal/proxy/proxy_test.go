package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type mockResolver struct {
	addrs map[string][]net.IPAddr
	err   error
}

func (m *mockResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if m.err != nil {
		return nil, m.err
	}
	addrs, ok := m.addrs[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host}
	}
	return addrs, nil
}

func ip(s string) net.IPAddr { return net.IPAddr{IP: net.ParseIP(s)} }

func testServer(t *testing.T, allow []string, ports []int, resolver Resolver) *Server {
	t.Helper()
	s, err := New(Options{
		Allow:      allow,
		AllowPorts: ports,
		LogDir:     t.TempDir(),
		Resolver:   resolver,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func proxyClient(proxyAddr string) *http.Client {
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}
}

func TestCheck(t *testing.T) {
	s, err := New(Options{
		Allow:      []string{"api.example.com", "*.example.com"},
		AllowPorts: []int{443, 80},
		LogDir:     t.TempDir(),
		Resolver:   &mockResolver{},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	tests := []struct {
		name   string
		host   string
		port   int
		wantOK bool
		substr string
	}{
		{"allowed host+port", "api.example.com", 443, true, ""},
		{"allowed wildcard", "foo.example.com", 443, true, ""},
		{"port not allowed", "api.example.com", 8080, false, "port 8080 not allowed"},
		{"host not allowed", "evil.com", 443, false, "not allowed"},
		{"IP literal v4", "1.2.3.4", 443, false, "IP literals"},
		{"IP literal v6", "::1", 443, false, "IP literals"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason, ok := s.check(tt.host, tt.port)
			if ok != tt.wantOK {
				t.Errorf("check(%q, %d) ok=%v, want %v (reason: %s)", tt.host, tt.port, ok, tt.wantOK, reason)
			}
			if !tt.wantOK && tt.substr != "" && !strings.Contains(reason, tt.substr) {
				t.Errorf("reason %q missing %q", reason, tt.substr)
			}
		})
	}

	// Empty ports denies all (fail closed)
	s2, _ := New(Options{
		Allow: []string{"api.example.com"}, AllowPorts: []int{},
		LogDir: t.TempDir(), Resolver: &mockResolver{},
	})
	defer s2.Close()
	if _, ok := s2.check("api.example.com", 443); ok {
		t.Error("empty ports should deny all")
	}
}

func TestResolvePublicIPs(t *testing.T) {
	resolver := &mockResolver{addrs: map[string][]net.IPAddr{
		"public.example.com":       {ip("93.184.216.34")},
		"multi.example.com":        {ip("93.184.216.34"), ip("198.51.100.1")},
		"private.example.com":      {ip("10.0.0.1")},
		"loopback.example.com":     {ip("127.0.0.1")},
		"linklocal.example.com":    {ip("169.254.1.1")},
		"ipv6private.example.com":  {ip("fc00::1")},
		"ipv6loopback.example.com": {ip("::1")},
		"mapped.example.com":       {ip("::ffff:10.0.0.1")},
		"mixed.example.com":        {ip("10.0.0.1"), ip("93.184.216.34")},
	}}

	s, err := New(Options{
		Allow: []string{"*.example.com"}, LogDir: t.TempDir(), Resolver: resolver,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	tests := []struct {
		name   string
		host   string
		wantOK bool
		wantN  int
		substr string
	}{
		{"public IP", "public.example.com", true, 1, ""},
		{"multiple public IPs", "multi.example.com", true, 2, ""},
		{"private IP", "private.example.com", false, 0, "DNS rebinding"},
		{"loopback", "loopback.example.com", false, 0, "DNS rebinding"},
		{"link-local", "linklocal.example.com", false, 0, "DNS rebinding"},
		{"IPv6 ULA", "ipv6private.example.com", false, 0, "DNS rebinding"},
		{"IPv6 loopback", "ipv6loopback.example.com", false, 0, "DNS rebinding"},
		{"IPv4-mapped IPv6 private", "mapped.example.com", false, 0, "DNS rebinding"},
		{"mixed filters private", "mixed.example.com", true, 1, ""},
		{"unknown host", "unknown.example.com", false, 0, "DNS resolution failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips, err := s.resolvePublicIPs(context.Background(), tt.host)
			if tt.wantOK {
				if err != nil {
					t.Errorf("error: %v", err)
				} else if len(ips) != tt.wantN {
					t.Errorf("got %d IPs, want %d", len(ips), tt.wantN)
				}
			} else {
				if err == nil {
					t.Errorf("should fail, got IPs %v", ips)
				} else if tt.substr != "" && !strings.Contains(err.Error(), tt.substr) {
					t.Errorf("error %q missing %q", err.Error(), tt.substr)
				}
			}
		})
	}
}

func TestIsPublicIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"93.184.216.34", true},
		{"8.8.8.8", true},
		{"2001:db8::1", true},
		{"::ffff:8.8.8.8", true},
		{"127.0.0.1", false},
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		{"192.168.1.1", false},
		{"169.254.1.1", false},
		{"::1", false},
		{"fe80::1", false},
		{"fc00::1", false},
		{"fd12::1", false},
		{"::ffff:10.0.0.1", false},
		{"::ffff:192.168.1.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			if got := isPublicIP(net.ParseIP(tt.ip)); got != tt.want {
				t.Errorf("isPublicIP(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestParseHostPort(t *testing.T) {
	tests := []struct {
		input    string
		wantHost string
		wantPort int
		wantErr  bool
	}{
		{"example.com:443", "example.com", 443, false},
		{"example.com:80", "example.com", 80, false},
		{"example.com:8080", "example.com", 8080, false},
		{"example.com", "", 0, true},
		{"example.com:abc", "", 0, true},
		{"example.com:0", "", 0, true},
		{"example.com:99999", "", 0, true},
		{"example.com:-1", "", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			h, p, err := parseHostPort(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseHostPort(%q) should fail", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if h != tt.wantHost || p != tt.wantPort {
				t.Errorf("got (%q, %d), want (%q, %d)", h, p, tt.wantHost, tt.wantPort)
			}
		})
	}
}

func TestReqHostPort(t *testing.T) {
	tests := []struct {
		rawURL   string
		wantHost string
		wantPort int
	}{
		{"http://example.com/path", "example.com", 80},
		{"https://example.com/path", "example.com", 443},
		{"http://example.com:8080/path", "example.com", 8080},
		{"https://example.com:9443/path", "example.com", 9443},
	}

	for _, tt := range tests {
		t.Run(tt.rawURL, func(t *testing.T) {
			u, _ := url.Parse(tt.rawURL)
			h, p, err := reqHostPort(&http.Request{URL: u, Host: u.Host})
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if h != tt.wantHost || p != tt.wantPort {
				t.Errorf("got (%q, %d), want (%q, %d)", h, p, tt.wantHost, tt.wantPort)
			}
		})
	}
}

func TestBlockLogger(t *testing.T) {
	t.Run("writes entries", func(t *testing.T) {
		dir := t.TempDir()
		bl, _ := newBlockLogger(dir)
		bl.log("evil.com", 443, "host not allowed")
		bl.log("bad.com", 80, "DNS rebinding")
		bl.close()

		content := string(must(os.ReadFile(filepath.Join(dir, "proxy.log"))))
		for _, want := range []string{"evil.com\t443\thost not allowed", "bad.com\t80\tDNS rebinding"} {
			if !strings.Contains(content, want) {
				t.Errorf("missing %q in log:\n%s", want, content)
			}
		}
	})

	t.Run("rotation on startup", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "proxy.log")
		os.WriteFile(path, make([]byte, maxLogSize+1), 0o600)

		bl, _ := newBlockLogger(dir)
		bl.log("test.com", 443, "test")
		bl.close()

		if info, err := os.Stat(path + ".1"); err != nil || info.Size() < maxLogSize {
			t.Error("proxy.log.1 should exist with old data")
		}
		if info, _ := os.Stat(path); info.Size() > 1024 {
			t.Error("new proxy.log should be small")
		}
	})

	t.Run("runtime rotation", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "proxy.log")
		bl, _ := newBlockLogger(dir)

		// Write enough to exceed maxLogSize
		big := strings.Repeat("x", 1024)
		for i := 0; i < (maxLogSize/1024)+10; i++ {
			bl.log("host.com", 443, big)
		}
		bl.close()

		if _, err := os.Stat(path + ".1"); err != nil {
			t.Error("proxy.log.1 should exist after runtime rotation")
		}
		if info, _ := os.Stat(path); info.Size() > maxLogSize {
			t.Error("proxy.log should have been rotated")
		}
	})

	t.Run("close is race-safe", func(t *testing.T) {
		bl, _ := newBlockLogger(t.TempDir())
		bl.close()
		bl.log("after.close.com", 443, "should not panic")
		if err := bl.close(); err != nil {
			t.Errorf("double Close() = %v", err)
		}
	})
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func TestProxyCONNECT(t *testing.T) {
	resolver := &mockResolver{addrs: map[string][]net.IPAddr{
		"allowed.example.com": {ip("93.184.216.34")},
		"blocked.example.com": {ip("93.184.216.34")},
	}}
	s := testServer(t, []string{"allowed.example.com"}, []int{443}, resolver)

	tests := []struct {
		name string
		host string
	}{
		{"blocked host", "blocked.example.com:443"},
		{"IP literal", "1.2.3.4:443"},
		{"port not allowed", "allowed.example.com:8080"},
		{"invalid port", "allowed.example.com:abc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", s.Addr, 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", tt.host, tt.host)
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 4096)
			n, _ := conn.Read(buf)
			if strings.Contains(string(buf[:n]), "200 OK") {
				t.Errorf("expected rejection, got: %s", strings.TrimSpace(string(buf[:n])))
			}
		})
	}
}

func TestProxyHTTP(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ts := &http.Server{Handler: mux}
	defer ts.Close()
	go ts.Serve(ln)

	port := ln.Addr().(*net.TCPAddr).Port
	targetAddr := ln.Addr().String()

	resolver := &mockResolver{addrs: map[string][]net.IPAddr{
		"allowed.example.com": {ip("93.184.216.34")},
		"blocked.example.com": {ip("93.184.216.34")},
	}}
	s := testServer(t, []string{"allowed.example.com"}, []int{port}, resolver)

	// Redirect dials to the local test server (DNS guard already ran in guardedDial)
	realDialer := s.dialer
	s.dialer = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return realDialer(ctx, network, targetAddr)
	}

	client := proxyClient(s.Addr)

	t.Run("allowed host forwards", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, fmt.Sprintf("http://allowed.example.com:%d/ok", port), nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "OK" {
			t.Errorf("body = %q, want OK", body)
		}
	})

	t.Run("blocked host returns 403", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, fmt.Sprintf("http://blocked.example.com:%d/ok", port), nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Errorf("status = %d, want 403", resp.StatusCode)
		}
	})

	t.Run("blocked port returns 403", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://allowed.example.com:9999/ok", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Errorf("status = %d, want 403", resp.StatusCode)
		}
	})
}

func TestServerLifecycle(t *testing.T) {
	s := testServer(t, []string{"api.example.com"}, []int{443}, &mockResolver{})
	if s.Addr == "" {
		t.Error("Addr should be set after Start()")
	}
	if s.proxy.Tr.Proxy != nil {
		t.Error("transport Proxy should be nil")
	}
	if s.proxy.ConnectDial == nil {
		t.Error("ConnectDial should be set")
	}
}
