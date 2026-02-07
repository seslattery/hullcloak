package proxy

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/elazarl/goproxy"

	"github.com/seslattery/hullcloak/internal/config"
)

// Options configures the proxy server.
type Options struct {
	Allow      []string
	AllowPorts []int
	LogDir     string
	Verbose    bool
	Resolver   Resolver
}

// Resolver resolves hostnames to IP addresses.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// Server is an HTTP proxy that enforces host and port allow-lists.
type Server struct {
	Addr     string
	opts     Options
	ports    map[int]struct{}
	proxy    *goproxy.ProxyHttpServer
	dialer   func(context.Context, string, string) (net.Conn, error)
	server   *http.Server
	listener net.Listener
	logger   *blockLogger
}

// New creates a new proxy Server with the given options.
func New(opts Options) (*Server, error) { //nolint:gocritic // opts is intentionally passed by value
	if opts.Resolver == nil {
		opts.Resolver = net.DefaultResolver
	}

	ports := make(map[int]struct{}, len(opts.AllowPorts))
	for _, p := range opts.AllowPorts {
		ports[p] = struct{}{}
	}

	bl, err := newBlockLogger(opts.LogDir)
	if err != nil {
		return nil, fmt.Errorf("proxy log: %w", err)
	}

	s := &Server{
		opts:   opts,
		ports:  ports,
		logger: bl,
		dialer: (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
	}
	s.proxy = goproxy.NewProxyHttpServer()
	s.proxy.Verbose = opts.Verbose
	if !opts.Verbose {
		s.proxy.Logger = log.New(os.Stderr, "", 0)
	}

	s.proxy.Tr = &http.Transport{
		Proxy:               nil,
		TLSHandshakeTimeout: 10 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return s.guardedDial(ctx, network, addr)
		},
	}
	s.proxy.ConnectDial = func(network, addr string) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return s.guardedDial(ctx, network, addr)
	}

	s.proxy.OnRequest().HandleConnectFunc(s.handleConnect)
	s.proxy.OnRequest().DoFunc(s.handleRequest)

	return s, nil
}

func (s *Server) guardedDial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %s", addr)
	}
	ips, err := s.resolvePublicIPs(ctx, host)
	if err != nil {
		s.logger.log(host, 0, err.Error())
		return nil, err
	}
	var lastErr error
	for _, ip := range ips {
		conn, err := s.dialer(ctx, network, net.JoinHostPort(ip.String(), portStr))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// Start begins listening and serving proxy requests.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("proxy listen: %w", err)
	}
	s.listener = ln
	s.Addr = ln.Addr().String()
	s.server = &http.Server{
		Handler:           s.proxy,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { _ = s.server.Serve(ln) }() //nolint:errcheck // best-effort; server shutdown handled by Close
	return nil
}

// Close shuts down the proxy server and its logger.
func (s *Server) Close() error {
	if s.server != nil {
		if err := s.server.Close(); err != nil {
			return err
		}
	}
	return s.logger.close()
}

func (s *Server) handleConnect(host string, ctx *goproxy.ProxyCtx) (action *goproxy.ConnectAction, newHost string) {
	h, port, err := parseHostPort(host)
	if err != nil {
		s.logger.log(host, 0, err.Error())
		return goproxy.RejectConnect, host
	}
	if reason, ok := s.check(h, port); !ok {
		s.logger.log(h, port, reason)
		return goproxy.RejectConnect, host
	}
	return goproxy.OkConnect, host
}

func (s *Server) handleRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if req.Method == http.MethodConnect {
		return req, nil
	}
	host, port, err := reqHostPort(req)
	if err != nil {
		return s.reject(req, req.URL.Host, 0, err.Error())
	}
	if reason, ok := s.check(host, port); !ok {
		return s.reject(req, host, port, reason)
	}
	return req, nil
}

func (s *Server) reject(req *http.Request, host string, port int, reason string) (*http.Request, *http.Response) {
	s.logger.log(host, port, reason)
	return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden,
		"blocked: "+reason)
}

func (s *Server) check(host string, port int) (reason string, ok bool) {
	if net.ParseIP(host) != nil {
		return "IP literals not supported", false
	}
	if _, allowed := s.ports[port]; !allowed {
		return fmt.Sprintf("port %d not allowed", port), false
	}
	if !s.hostAllowed(host) {
		return fmt.Sprintf("host %s not allowed", host), false
	}
	return "", true
}

func (s *Server) hostAllowed(host string) bool {
	for _, pattern := range s.opts.Allow {
		if config.MatchHost(pattern, host) {
			return true
		}
	}
	return false
}

func (s *Server) resolvePublicIPs(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if isPublicIP(ip) {
			return []net.IP{ip}, nil
		}
		return nil, fmt.Errorf("IP literal %s is not a public address", host)
	}

	addrs, err := s.opts.Resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed: %v", err)
	}
	var public []net.IP
	for _, addr := range addrs {
		if isPublicIP(addr.IP) {
			public = append(public, addr.IP)
		}
	}
	if len(public) == 0 {
		return nil, fmt.Errorf("DNS rebinding: %s resolves to private/loopback IPs only", host)
	}
	return public, nil
}

func isPublicIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() ||
		addr.IsInterfaceLocalMulticast() {
		return false
	}

	for _, prefix := range blockedSpecialPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

var blockedSpecialPrefixes = []netip.Prefix{
	// IPv4 special-use networks that are not globally reachable.
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("192.88.99.0/24"),  // 6to4 relay anycast
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmark testing
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved/future use

	// IPv6 special-use/doc/testing ranges.
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:2::/48"),   // benchmarking
	netip.MustParsePrefix("2001:db8::/32"), // documentation
	netip.MustParsePrefix("2001:10::/28"),  // ORCHID
}

func parseHostPort(hostport string) (host string, port int, err error) {
	h, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", 0, fmt.Errorf("invalid host:port %q", hostport)
	}
	port, err = strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port in %q", hostport)
	}
	return h, port, nil
}

func reqHostPort(req *http.Request) (host string, port int, err error) {
	h := req.URL.Hostname()
	p := req.URL.Port()
	if h == "" {
		h = req.Host
		if hh, pp, err := net.SplitHostPort(h); err == nil {
			h, p = hh, pp
		}
	}
	if p == "" {
		if req.URL.Scheme == "https" {
			p = "443"
		} else {
			p = "80"
		}
	}
	port, err = strconv.Atoi(p)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port %q", p)
	}
	return h, port, nil
}

type blockLogger struct {
	mu   sync.Mutex
	file *os.File
	path string
}

const maxLogSize = 10 << 20 // 10 MB

func newBlockLogger(dir string) (*blockLogger, error) {
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		dir = filepath.Join(home, ".hullcloak")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}

	path := filepath.Join(dir, "proxy.log")
	rotated := path + ".1"

	if info, err := os.Stat(path); err == nil && info.Size() > maxLogSize {
		os.Remove(rotated)       //nolint:errcheck,gosec // best-effort cleanup
		os.Rename(path, rotated) //nolint:errcheck,gosec // best-effort rotation
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // path is constructed internally
	if err != nil {
		return nil, err
	}
	return &blockLogger{file: f, path: path}, nil
}

func (l *blockLogger) log(host string, port int, reason string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return
	}
	fmt.Fprintf(l.file, "%s\t%s\t%d\t%s\n", //nolint:errcheck // best-effort log write
		time.Now().Format(time.RFC3339), host, port, reason)
	l.maybeRotate()
}

func (l *blockLogger) maybeRotate() {
	info, err := l.file.Stat()
	if err != nil {
		log.Printf("proxy log stat: %v", err)
		return
	}
	if info.Size() <= maxLogSize {
		return
	}
	rotated := l.path + ".1"
	l.file.Close()                                                            //nolint:errcheck,gosec // best-effort; reopening immediately
	os.Remove(rotated)                                                        //nolint:errcheck,gosec // best-effort cleanup
	os.Rename(l.path, rotated)                                                //nolint:errcheck,gosec // best-effort rotation
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // path is constructed internally
	if err != nil {
		log.Printf("proxy log reopen: %v", err)
		l.file = nil
		return
	}
	l.file = f
}

func (l *blockLogger) close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}
