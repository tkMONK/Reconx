package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/miekg/dns"
)

const version = "1.0"

// ──────────────────────────────────────────────────────────────────────────────
// COLORS & FORMATTING
// ──────────────────────────────────────────────────────────────────────────────

var (
	cRed      = color.New(color.FgRed).SprintFunc()
	cGreen    = color.New(color.FgGreen).SprintFunc()
	cYellow   = color.New(color.FgYellow).SprintFunc()
	cCyan     = color.New(color.FgCyan).SprintFunc()
	cBlue     = color.New(color.FgBlue).SprintFunc()
	cMagenta  = color.New(color.FgMagenta).SprintFunc()
	cWhite    = color.New(color.FgWhite).SprintFunc()
	cBold     = color.New(color.Bold).SprintFunc()
	cHiGreen  = color.New(color.FgHiGreen).SprintFunc()
	cHiYellow = color.New(color.FgHiYellow).SprintFunc()
	cHiWhite  = color.New(color.FgHiWhite).SprintFunc()

	// jsonOnly suppresses terminal output when set
	quietMode bool
)

func banner() {
	if quietMode {
		return
	}
	fmt.Println()
	fmt.Println(cBold(cCyan("  ┌─────────────────────────────────────┐")))
	fmt.Println(cBold(cCyan("  │         RECONX  v" + version + "    │")))
	fmt.Println(cBold(cCyan("  │  Active & Passive Recon Tool        │")))
	fmt.Println(cBold(cCyan("  └─────────────────────────────────────┘")))
	fmt.Println()
}

// ──────────────────────────────────────────────────────────────────────────────
// DATA STRUCTURES
// ──────────────────────────────────────────────────────────────────────────────

type DNSRecord struct {
	Type   string   `json:"type"`
	Values []string `json:"values"`
}

type ZoneTransferResult struct {
	Server  string   `json:"server"`
	Success bool     `json:"success"`
	Records []string `json:"records,omitempty"`
}

type SubdomainSource struct {
	Source    string   `json:"source"`
	Subdomains []string `json:"subdomains"`
}

type SSLInfo struct {
	Issuer      string   `json:"issuer"`
	Subject     string   `json:"subject"`
	NotBefore   string   `json:"not_before"`
	NotAfter    string   `json:"not_after"`
	SANs        []string `json:"sans"`
	Protocols   []string `json:"protocols"`
	CipherSuite string   `json:"cipher_suite"`
	IsExpired   bool     `json:"is_expired"`
	ExpiresSoon bool     `json:"expires_soon"`
}

type GeoIPInfo struct {
	IP      string `json:"ip"`
	Country string `json:"country"`
	Region  string `json:"region"`
	City    string `json:"city"`
	ISP     string `json:"isp"`
	Org     string `json:"org"`
	ASN     string `json:"asn"`
}

type SecurityHeaderResult struct {
	Header  string `json:"header"`
	Present bool   `json:"present"`
	Value   string `json:"value,omitempty"`
}

type WebInfo struct {
	Headers         map[string]string      `json:"headers"`
	Technologies    []string               `json:"technologies"`
	RobotsPaths     []string               `json:"robots_paths"`
	SitemapStatus   string                 `json:"sitemap_status"`
	RedirectURL     string                 `json:"redirect_url"`
	ResponseCode    int                    `json:"response_code"`
	Title           string                 `json:"title"`
	SecurityHeaders []SecurityHeaderResult `json:"security_headers"`
	SecurityScore   int                    `json:"security_header_score"`
}

type EmailRecon struct {
	SPF    []string `json:"spf"`
	DMARC  string   `json:"dmarc"`
	DKIM   []string `json:"dkim_selectors_found"`
	BIMI   string   `json:"bimi,omitempty"`
	MXSec  []string `json:"mx_security_notes"`
	Emails []string `json:"emails"`
}

type ReconResults struct {
	Target        string               `json:"target"`
	Timestamp     string               `json:"timestamp"`
	DNSRecords    []DNSRecord          `json:"dns_records"`
	Whois         string               `json:"whois"`
	ZoneTransfers []ZoneTransferResult `json:"zone_transfers"`
	Subdomains    []SubdomainSource    `json:"subdomains"`
	AllSubdomains []string             `json:"all_subdomains_unique"`
	SSLInfo       *SSLInfo             `json:"ssl_info,omitempty"`
	GeoIP         *GeoIPInfo           `json:"geoip,omitempty"`
	WebInfo       *WebInfo             `json:"web_info,omitempty"`
	EmailRecon    *EmailRecon          `json:"email_recon,omitempty"`
	WaybackURLs   []string             `json:"wayback_urls"`
}

// ──────────────────────────────────────────────────────────────────────────────
// UTILITIES
// ──────────────────────────────────────────────────────────────────────────────

func section(title string) {
	if quietMode {
		return
	}
	fmt.Println()
	fmt.Println(cYellow("┌" + strings.Repeat("─", 62) + "┐"))
	pad := 62 - len("  "+title)
	if pad < 0 {
		pad = 0
	}
	fmt.Println(cYellow("│") + cHiWhite("  "+title) + cYellow(strings.Repeat(" ", pad)+"│"))
	fmt.Println(cYellow("└" + strings.Repeat("─", 62) + "┘"))
}

func info(msg string) {
	if !quietMode {
		fmt.Printf(" %s %s\n", cCyan("[*]"), msg)
	}
}
func success(msg string) {
	if !quietMode {
		fmt.Printf(" %s %s\n", cGreen("[+]"), msg)
	}
}
func warn(msg string) {
	if !quietMode {
		fmt.Printf(" %s %s\n", cYellow("[!]"), msg)
	}
}
func errMsg(msg string) {
	if !quietMode {
		fmt.Printf(" %s %s\n", cRed("[-]"), msg)
	}
}
func result(msg string) {
	if !quietMode {
		fmt.Printf("     %s\n", cHiWhite(msg))
	}
}
func divider() {
	if !quietMode {
		fmt.Println(cBlue("  " + strings.Repeat("─", 54)))
	}
}

// httpClient with reasonable timeout and TLS flexibility.
// InsecureSkipVerify is intentional for recon against misconfigured targets.
var httpClient = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		MaxIdleConns:        20,
		MaxIdleConnsPerHost: 5,
		IdleConnTimeout:     30 * time.Second,
	},
	// Do not follow redirects automatically so we can capture them.
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	},
}

// makeRequest performs a GET and returns the body. It accepts any 2xx status.
func makeRequest(url string) ([]byte, error) {
	return makeRequestCtx(context.Background(), url)
}

func makeRequestCtx(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconX/"+version+"; +https://github.com/reconx)")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024)) // 5 MB cap
}

func dedupe(slice []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range slice {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func clamp(n, max int) int {
	if n < max {
		return n
	}
	return max
}

// ──────────────────────────────────────────────────────────────────────────────
// DNS RECON
// ──────────────────────────────────────────────────────────────────────────────

func runDNSRecon(domain string) []DNSRecord {
	section("DNS RECONNAISSANCE (Passive)")

	recordTypes := []string{"A", "AAAA", "NS", "MX", "TXT", "SOA", "CNAME", "SRV", "CAA", "PTR", "HINFO"}
	var records []DNSRecord

	for _, rtype := range recordTypes {
		info(fmt.Sprintf("Querying %s records...", rtype))
		vals := queryDNS(domain, rtype)
		if len(vals) > 0 {
			result(fmt.Sprintf("%s → %s", rtype, strings.Join(vals, ", ")))
			records = append(records, DNSRecord{Type: rtype, Values: vals})
		} else {
			result(fmt.Sprintf("%s → none", rtype))
			records = append(records, DNSRecord{Type: rtype, Values: []string{}})
		}
		divider()
	}

	return records
}

func queryDNS(domain, rtype string) []string {
	dnsType, ok := dns.StringToType[rtype]
	if !ok {
		return nil
	}

	conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || len(conf.Servers) == 0 {
		conf = &dns.ClientConfig{Servers: []string{"8.8.8.8", "1.1.1.1"}, Port: "53"}
	}

	c := new(dns.Client)
	c.Timeout = 5 * time.Second

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dnsType)
	m.RecursionDesired = true

	var allValues []string
	for _, server := range conf.Servers {
		addr := net.JoinHostPort(server, conf.Port)
		r, _, err := c.Exchange(m, addr)
		if err != nil || r == nil {
			continue
		}

		for _, ans := range r.Answer {
			switch rr := ans.(type) {
			case *dns.A:
				allValues = append(allValues, rr.A.String())
			case *dns.AAAA:
				allValues = append(allValues, rr.AAAA.String())
			case *dns.NS:
				allValues = append(allValues, strings.TrimSuffix(rr.Ns, "."))
			case *dns.MX:
				allValues = append(allValues, fmt.Sprintf("%d %s", rr.Preference, strings.TrimSuffix(rr.Mx, ".")))
			case *dns.TXT:
				allValues = append(allValues, strings.Join(rr.Txt, " "))
			case *dns.SOA:
				allValues = append(allValues, fmt.Sprintf("%s %s serial=%d",
					strings.TrimSuffix(rr.Ns, "."),
					strings.TrimSuffix(rr.Mbox, "."),
					rr.Serial))
			case *dns.CNAME:
				allValues = append(allValues, strings.TrimSuffix(rr.Target, "."))
			case *dns.SRV:
				allValues = append(allValues, fmt.Sprintf("priority=%d weight=%d port=%d target=%s",
					rr.Priority, rr.Weight, rr.Port, strings.TrimSuffix(rr.Target, ".")))
			case *dns.CAA:
				allValues = append(allValues, fmt.Sprintf("flag=%d tag=%s value=%q", rr.Flag, rr.Tag, rr.Value))
			case *dns.PTR:
				allValues = append(allValues, strings.TrimSuffix(rr.Ptr, "."))
			case *dns.HINFO:
				allValues = append(allValues, fmt.Sprintf("cpu=%s os=%s", rr.Cpu, rr.Os))
			}
		}
		if len(allValues) > 0 {
			break
		}
	}

	return dedupe(allValues)
}

// ──────────────────────────────────────────────────────────────────────────────
// WHOIS
// ──────────────────────────────────────────────────────────────────────────────

func runWHOIS(domain string) string {
	section("WHOIS LOOKUP (Passive)")
	info("Running WHOIS on " + domain + "...")

	text, err := whoisLookup(domain)
	if err != nil {
		errMsg("WHOIS failed: " + err.Error())
		return ""
	}

	keyFields := []string{
		"registrar", "creation", "expir", "updated", "name server",
		"status", "registrant", "admin", "tech", "country", "email",
		"organisation", "org:", "created:", "expires:", "changed:",
	}

	var filtered []string
	for _, line := range strings.Split(text, "\n") {
		lower := strings.ToLower(line)
		if strings.HasPrefix(strings.TrimSpace(line), "%") {
			continue
		}
		for _, key := range keyFields {
			if strings.Contains(lower, key) {
				filtered = append(filtered, strings.TrimSpace(line))
				break
			}
		}
	}

	output := strings.Join(filtered, "\n")
	if output == "" {
		result("No structured WHOIS data found")
		return text
	}
	for _, line := range filtered {
		result(line)
	}
	return output
}

func whoisLookup(domain string) (string, error) {
	conn, err := net.DialTimeout("tcp", "whois.iana.org:43", 10*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	fmt.Fprintf(conn, domain+"\r\n")
	conn.SetDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck

	raw, _ := io.ReadAll(conn)
	text := string(raw)

	// Follow referral to the registrar WHOIS server
	referralRe := regexp.MustCompile(`(?i)whois:\s+(\S+)`)
	match := referralRe.FindStringSubmatch(text)
	if len(match) > 1 && !strings.Contains(match[1], "iana.org") {
		server := match[1]
		conn2, err := net.DialTimeout("tcp", server+":43", 10*time.Second)
		if err == nil {
			defer conn2.Close()
			fmt.Fprintf(conn2, domain+"\r\n")
			conn2.SetDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
			raw2, _ := io.ReadAll(conn2)
			return string(raw2), nil
		}
	}
	return text, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// ZONE TRANSFER
// ──────────────────────────────────────────────────────────────────────────────

func runZoneTransfers(domain string) []ZoneTransferResult {
	section("DNS ZONE TRANSFER CHECK (Active)")
	info("Attempting AXFR zone transfers against NS records...")

	// FIX: use NS records only — not A records (IPs can't serve DNS zone transfers)
	nsRecords := queryDNS(domain, "NS")
	if len(nsRecords) == 0 {
		warn("No NS records found for zone transfer")
		return nil
	}

	var results []ZoneTransferResult

	for _, ns := range nsRecords {
		ns = strings.TrimSuffix(strings.TrimSpace(ns), ".")
		info(fmt.Sprintf("Attempting zone transfer from %s...", cBold(ns)))

		t := new(dns.Transfer)
		m := new(dns.Msg)
		m.SetAxfr(dns.Fqdn(domain))

		server := ns
		if !strings.Contains(server, ":") {
			server = net.JoinHostPort(server, "53")
		}

		ch, err := t.In(m, server)
		if err != nil {
			warn(fmt.Sprintf("Zone transfer rejected by %s: %v", ns, err))
			results = append(results, ZoneTransferResult{Server: ns, Success: false})
			continue
		}

		var records []string
		for env := range ch {
			if env.Error != nil {
				break
			}
			for _, rr := range env.RR {
				records = append(records, rr.String())
			}
		}

		if len(records) > 0 {
			success(fmt.Sprintf("Zone transfer SUCCESSFUL on %s! (%d records)", ns, len(records)))
			for _, rec := range records[:clamp(len(records), 20)] {
				result(rec)
			}
			if len(records) > 20 {
				result(fmt.Sprintf("... and %d more records", len(records)-20))
			}
			results = append(results, ZoneTransferResult{Server: ns, Success: true, Records: records})
		} else {
			warn("Zone transfer not allowed on " + ns)
			results = append(results, ZoneTransferResult{Server: ns, Success: false})
		}
	}

	return results
}

// ──────────────────────────────────────────────────────────────────────────────
// SUBDOMAIN ENUMERATION (Concurrent, Multiple Sources)
// ──────────────────────────────────────────────────────────────────────────────

func runSubdomainEnum(domain string) []SubdomainSource {
	section("SUBDOMAIN ENUMERATION (Passive + Active)")

	sources := []struct {
		name string
		fn   func(string) []string
	}{
		{"crt.sh", subdomainCRTSH},
		{"SecurityTrails", subdomainSecurityTrails},
		{"HackerTarget", subdomainHackerTarget},
		{"RapidDNS", subdomainRapidDNS},
		{"AlienVault OTX", subdomainAlienVault},
		{"CertSpotter", subdomainCertSpotter},
		{"AnubisDB", subdomainAnubisDB},
		{"C99", subdomainC99},
		{"Wayback URLs", subdomainWayback},
		{"BufferOver", subdomainBufferOver},
	}

	type sourceResult struct {
		name string
		subs []string
	}

	resultCh := make(chan sourceResult, len(sources))
	var wg sync.WaitGroup

	for _, src := range sources {
		wg.Add(1)
		go func(name string, fn func(string) []string) {
			defer wg.Done()
			subs := fn(domain)
			resultCh <- sourceResult{name: name, subs: subs}
		}(src.name, src.fn)
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	var allSubdomains []string
	var enumResults []SubdomainSource

	for r := range resultCh {
		if len(r.subs) > 0 {
			result(fmt.Sprintf("[%s] Found %d subdomains", r.name, len(r.subs)))
			for _, s := range r.subs[:clamp(len(r.subs), 10)] {
				result("  └─ " + s)
			}
			if len(r.subs) > 10 {
				result(fmt.Sprintf("  └─ ... and %d more", len(r.subs)-10))
			}
			allSubdomains = append(allSubdomains, r.subs...)
			enumResults = append(enumResults, SubdomainSource{
				Source:    r.name,
				Subdomains: r.subs,
			})
		} else {
			result(fmt.Sprintf("[%s] No subdomains found", r.name))
		}
		divider()
	}

	allUnique := dedupe(allSubdomains)
	success(fmt.Sprintf("Total unique subdomains found: %d", len(allUnique)))

	return enumResults
}

func subdomainCRTSH(domain string) []string {
	body, err := makeRequest(fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain))
	if err != nil {
		return nil
	}

	var entries []map[string]interface{}
	if json.Unmarshal(body, &entries) != nil {
		// Fall back to regex if JSON parse fails
		re := regexp.MustCompile(`"name_value"\s*:\s*"([^"]+)"`)
		matches := re.FindAllStringSubmatch(string(body), -1)
		var subs []string
		for _, m := range matches {
			for _, sub := range strings.Split(m[1], "\n") {
				sub = strings.TrimSpace(strings.TrimPrefix(sub, "*."))
				if sub != "" && strings.HasSuffix(sub, domain) {
					subs = append(subs, sub)
				}
			}
		}
		return dedupe(subs)
	}

	var subs []string
	for _, entry := range entries {
		nameVal, _ := entry["name_value"].(string)
		for _, sub := range strings.Split(nameVal, "\n") {
			sub = strings.TrimSpace(strings.TrimPrefix(sub, "*."))
			if sub != "" && strings.HasSuffix(sub, domain) {
				subs = append(subs, sub)
			}
		}
	}
	return dedupe(subs)
}

func subdomainSecurityTrails(domain string) []string {
	body, err := makeRequest(fmt.Sprintf("https://securitytrails.com/subdomain-tracker?domain=%s", domain))
	if err != nil {
		return nil
	}
	re := regexp.MustCompile(`[a-zA-Z0-9._-]+\.` + regexp.QuoteMeta(domain))
	return dedupe(re.FindAllString(string(body), -1))
}

func subdomainHackerTarget(domain string) []string {
	body, err := makeRequest(fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain))
	if err != nil {
		return nil
	}
	var subs []string
	for _, line := range strings.Split(string(body), "\n") {
		parts := strings.SplitN(line, ",", 2)
		if len(parts) >= 1 && strings.Contains(parts[0], "."+domain) {
			subs = append(subs, strings.TrimSpace(parts[0]))
		}
	}
	return dedupe(subs)
}

func subdomainRapidDNS(domain string) []string {
	body, err := makeRequest(fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1", domain))
	if err != nil {
		return nil
	}
	re := regexp.MustCompile(`<td[^>]*>([a-zA-Z0-9._-]+\.` + regexp.QuoteMeta(domain) + `)</td>`)
	matches := re.FindAllStringSubmatch(string(body), -1)
	var subs []string
	for _, m := range matches {
		subs = append(subs, m[1])
	}
	return dedupe(subs)
}

func subdomainAlienVault(domain string) []string {
	body, err := makeRequest(fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain))
	if err != nil {
		return nil
	}
	re := regexp.MustCompile(`"hostname"\s*:\s*"([^"]+\.` + regexp.QuoteMeta(domain) + `)"`)
	matches := re.FindAllStringSubmatch(string(body), -1)
	var subs []string
	for _, m := range matches {
		subs = append(subs, m[1])
	}
	return dedupe(subs)
}

func subdomainCertSpotter(domain string) []string {
	body, err := makeRequest(fmt.Sprintf(
		"https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain))
	if err != nil {
		return nil
	}
	re := regexp.MustCompile(`"dns_names"\s*:\s*\[([^\]]+)\]`)
	matches := re.FindAllStringSubmatch(string(body), -1)
	var subs []string
	for _, m := range matches {
		namesRe := regexp.MustCompile(`"([^"]+)"`)
		for _, nm := range namesRe.FindAllStringSubmatch(m[1], -1) {
			name := strings.TrimPrefix(nm[1], "*.")
			if strings.HasSuffix(name, domain) {
				subs = append(subs, name)
			}
		}
	}
	return dedupe(subs)
}

func subdomainAnubisDB(domain string) []string {
	body, err := makeRequest(fmt.Sprintf("https://jonlu.ca/anubis/lookup?host=%s", domain))
	if err != nil {
		return nil
	}
	var subs []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasSuffix(line, "."+domain) {
			subs = append(subs, line)
		}
	}
	return dedupe(subs)
}

func subdomainC99(domain string) []string {
	body, err := makeRequest(fmt.Sprintf("https://subdomainfinder.c99.nl/search?domain=%s", domain))
	if err != nil {
		return nil
	}
	re := regexp.MustCompile(`([a-zA-Z0-9._-]+\.` + regexp.QuoteMeta(domain) + `)`)
	return dedupe(re.FindAllString(string(body), -1))
}

func subdomainWayback(domain string) []string {
	body, err := makeRequest(fmt.Sprintf(
		"https://web.archive.org/cdx/search/cdx?url=*.%s/*&output=text&fl=original&collapse=urlkey&limit=1000",
		domain))
	if err != nil {
		return nil
	}
	re := regexp.MustCompile(`https?://([a-zA-Z0-9._-]+\.` + regexp.QuoteMeta(domain) + `)`)
	matches := re.FindAllStringSubmatch(string(body), -1)
	var subs []string
	for _, m := range matches {
		subs = append(subs, m[1])
	}
	return dedupe(subs)
}

// subdomainBufferOver is an additional passive source
func subdomainBufferOver(domain string) []string {
	body, err := makeRequest(fmt.Sprintf("https://dns.bufferover.run/dns?q=.%s", domain))
	if err != nil {
		return nil
	}
	re := regexp.MustCompile(`([a-zA-Z0-9._-]+\.` + regexp.QuoteMeta(domain) + `)`)
	return dedupe(re.FindAllString(string(body), -1))
}

// ──────────────────────────────────────────────────────────────────────────────
// WEB TECHNOLOGY DISCOVERY
// ──────────────────────────────────────────────────────────────────────────────

func runWebRecon(domain string) *WebInfo {
	section("WEB TECHNOLOGY DISCOVERY")

	webInfo := &WebInfo{
		Headers: make(map[string]string),
	}

	targetURL := "https://" + domain
	resp, err := httpClient.Get(targetURL)
	if err != nil {
		info(fmt.Sprintf("HTTPS failed, trying HTTP for %s ...", domain))
		resp, err = httpClient.Get("http://" + domain)
		if err != nil {
			errMsg("Failed to connect via HTTP or HTTPS: " + err.Error())
			return webInfo
		}
		targetURL = "http://" + domain
	}
	defer resp.Body.Close()

	webInfo.ResponseCode = resp.StatusCode
	finalURL := resp.Request.URL.String()
	webInfo.RedirectURL = finalURL

	if finalURL != targetURL {
		result(fmt.Sprintf("Redirect: %s → %s", targetURL, finalURL))
	}
	result(fmt.Sprintf("HTTP Status: %d", resp.StatusCode))

	// Store and display headers
	for key, values := range resp.Header {
		webInfo.Headers[key] = strings.Join(values, ", ")
	}

	displayHeaders := []string{
		"Server", "X-Powered-By", "X-AspNet-Version", "X-Generator",
		"X-Frame-Options", "Strict-Transport-Security", "X-XSS-Protection",
		"Content-Security-Policy", "X-Content-Type-Options", "Content-Type",
		"Via", "X-Varnish", "CF-Ray", "X-Cache",
	}

	info("HTTP Headers:")
	for _, h := range displayHeaders {
		if val, ok := resp.Header[h]; ok {
			result(fmt.Sprintf("%s: %s", h, val[0]))
			if tech := detectTechnology(h, val[0]); tech != "" {
				webInfo.Technologies = append(webInfo.Technologies, tech)
			}
		}
	}

	// Security header audit
	divider()
	webInfo.SecurityHeaders, webInfo.SecurityScore = auditSecurityHeaders(resp.Header)
	info(fmt.Sprintf("Security Header Score: %d / 6", webInfo.SecurityScore))
	for _, sh := range webInfo.SecurityHeaders {
		if sh.Present {
			result(fmt.Sprintf("  %s ✓ %s", cGreen("[PRESENT]"), sh.Header))
		} else {
			result(fmt.Sprintf("  %s ✗ %s", cRed("[MISSING]"), sh.Header))
		}
	}

	// Technology detection from body
	divider()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 50000))
	bodyStr := string(body)
	bodyStrLower := strings.ToLower(bodyStr)

	titleRe := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)`)
	if m := titleRe.FindStringSubmatch(bodyStr); len(m) > 1 {
		webInfo.Title = strings.TrimSpace(m[1])
		result(fmt.Sprintf("Page Title: %s", webInfo.Title))
	}

	bodyTechnologies := map[string]string{
		"wp-content":  "WordPress",
		"wp-includes": "WordPress",
		"/skin/":      "Magento",
		"shopify":     "Shopify",
		"wix.com":     "Wix",
		"squarespace": "Squarespace",
		"react":       "React",
		"angular":     "Angular",
		"vue.js":      "Vue.js",
		"jquery":      "jQuery",
		"bootstrap":   "Bootstrap",
		"laravel":     "Laravel",
		"django":      "Django",
		"rails":       "Ruby on Rails",
		"express":     "Express.js",
		"next.js":     "Next.js",
		"gatsby":      "Gatsby",
		"nuxt":        "Nuxt.js",
		"svelte":      "Svelte",
	}

	for pattern, tech := range bodyTechnologies {
		if strings.Contains(bodyStrLower, pattern) {
			webInfo.Technologies = append(webInfo.Technologies, tech)
		}
	}
	webInfo.Technologies = dedupe(webInfo.Technologies)

	if len(webInfo.Technologies) > 0 {
		divider()
		info("Detected Technologies:")
		for _, t := range webInfo.Technologies {
			result("└─ " + t)
		}
	}

	// robots.txt
	divider()
	info("Checking robots.txt...")
	resp2, err := httpClient.Get("https://" + domain + "/robots.txt")
	if err == nil {
		defer resp2.Body.Close()
		if resp2.StatusCode == 200 {
			robotsBody, _ := io.ReadAll(io.LimitReader(resp2.Body, 10000))
			var paths []string
			for _, line := range strings.Split(string(robotsBody), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "Disallow:") || strings.HasPrefix(line, "Allow:") {
					path := strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
					if path != "" && path != "/" {
						paths = append(paths, path)
						if len(paths) <= 15 {
							result(line)
						}
					}
				}
			}
			if len(paths) > 15 {
				result(fmt.Sprintf("... and %d more paths", len(paths)-15))
			}
			webInfo.RobotsPaths = paths
		} else {
			result("robots.txt: " + resp2.Status)
		}
	} else {
		result("robots.txt not found")
	}

	// sitemap.xml
	divider()
	info("Checking sitemap.xml...")
	resp3, err := httpClient.Get("https://" + domain + "/sitemap.xml")
	if err == nil {
		defer resp3.Body.Close()
		webInfo.SitemapStatus = resp3.Status
		result(fmt.Sprintf("sitemap.xml: %s", resp3.Status))
	} else {
		result("sitemap.xml not found")
	}

	return webInfo
}

// auditSecurityHeaders checks for the presence of important security headers
// and returns a score out of 6.
func auditSecurityHeaders(headers http.Header) ([]SecurityHeaderResult, int) {
	criticalHeaders := []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Content-Type-Options",
		"X-Frame-Options",
		"Referrer-Policy",
		"Permissions-Policy",
	}

	var results []SecurityHeaderResult
	score := 0
	for _, h := range criticalHeaders {
		val := headers.Get(h)
		present := val != ""
		if present {
			score++
		}
		results = append(results, SecurityHeaderResult{
			Header:  h,
			Present: present,
			Value:   val,
		})
	}
	return results, score
}

func detectTechnology(header, value string) string {
	valueLower := strings.ToLower(value)
	techMap := map[string]string{
		"apache":     "Apache",
		"nginx":      "Nginx",
		"iis":        "Microsoft IIS",
		"cloudflare": "Cloudflare",
		"akamai":     "Akamai",
		"php":        "PHP",
		"asp.net":    "ASP.NET",
		"express":    "Express.js",
		"python":     "Python",
		"java":       "Java",
		"node.js":    "Node.js",
		"wordpress":  "WordPress",
		"drupal":     "Drupal",
		"joomla":     "Joomla",
		"prestashop": "PrestaShop",
		"shopify":    "Shopify",
		"magento":    "Magento",
		"tomcat":     "Apache Tomcat",
		"gunicorn":   "Gunicorn",
		"varnish":    "Varnish",
		"fastly":     "Fastly",
		"google":     "Google Cloud",
		"aws":        "AWS",
		"litespeed":  "LiteSpeed",
		"caddy":      "Caddy",
	}

	for pattern, tech := range techMap {
		if strings.Contains(valueLower, pattern) {
			return tech
		}
	}
	return ""
}

// ──────────────────────────────────────────────────────────────────────────────
// SSL/TLS ANALYSIS
// ──────────────────────────────────────────────────────────────────────────────

func runSSLRecon(domain string) *SSLInfo {
	section("SSL/TLS CERTIFICATE ANALYSIS")
	info("Fetching SSL certificate info...")

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp", domain+":443",
		&tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	)
	if err != nil {
		errMsg("SSL connection failed: " + err.Error())
		return nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		errMsg("No certificates presented by server")
		return nil
	}
	cert := state.PeerCertificates[0]

	sslInfo := &SSLInfo{
		Issuer:      cert.Issuer.CommonName,
		Subject:     cert.Subject.CommonName,
		NotBefore:   cert.NotBefore.Format("2006-01-02"),
		NotAfter:    cert.NotAfter.Format("2006-01-02"),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		SANs:        cert.DNSNames,
	}

	protocols := map[uint16]string{
		tls.VersionTLS10: "TLS 1.0",
		tls.VersionTLS11: "TLS 1.1",
		tls.VersionTLS12: "TLS 1.2",
		tls.VersionTLS13: "TLS 1.3",
	}
	if proto, ok := protocols[state.Version]; ok {
		sslInfo.Protocols = []string{proto}
	}

	result(fmt.Sprintf("Issuer: %s", sslInfo.Issuer))
	result(fmt.Sprintf("Subject: %s", sslInfo.Subject))
	result(fmt.Sprintf("Valid: %s → %s", sslInfo.NotBefore, sslInfo.NotAfter))
	result(fmt.Sprintf("Cipher: %s", sslInfo.CipherSuite))
	result(fmt.Sprintf("Protocol: %s", strings.Join(sslInfo.Protocols, ", ")))

	if len(sslInfo.SANs) > 0 {
		divider()
		info(fmt.Sprintf("Subject Alternative Names (%d):", len(sslInfo.SANs)))
		for _, san := range sslInfo.SANs[:clamp(len(sslInfo.SANs), 15)] {
			result("└─ " + san)
		}
		if len(sslInfo.SANs) > 15 {
			result(fmt.Sprintf("└─ ... and %d more", len(sslInfo.SANs)-15))
		}
	}

	now := time.Now()
	if cert.NotAfter.Before(now) {
		sslInfo.IsExpired = true
		warn("⚠ CERTIFICATE IS EXPIRED!")
	} else if cert.NotAfter.Before(now.Add(30 * 24 * time.Hour)) {
		sslInfo.ExpiresSoon = true
		warn(fmt.Sprintf("⚠ Certificate expires in %d days!", int(cert.NotAfter.Sub(now).Hours()/24)))
	} else {
		success(fmt.Sprintf("Certificate valid for %d more days", int(cert.NotAfter.Sub(now).Hours()/24)))
	}

	// Warn about weak protocols
	if state.Version == tls.VersionTLS10 || state.Version == tls.VersionTLS11 {
		warn("⚠ Weak TLS version in use! Consider upgrading to TLS 1.2 or 1.3")
	}

	return sslInfo
}

// ──────────────────────────────────────────────────────────────────────────────
// EMAIL / OSINT RECON
// ──────────────────────────────────────────────────────────────────────────────

// dkimSelectors are common DKIM selectors to probe
var dkimSelectors = []string{
	"default", "google", "mail", "k1", "k2", "selector1", "selector2",
	"dkim", "email", "smtp", "s1", "s2", "zoho", "mailchimp", "sendgrid",
}

func runEmailRecon(domain string) *EmailRecon {
	section("EMAIL & OSINT (Passive)")

	emailRecon := &EmailRecon{}

	// SPF
	info("Checking SPF record...")
	for _, r := range queryDNS(domain, "TXT") {
		if strings.Contains(strings.ToLower(r), "v=spf1") {
			emailRecon.SPF = append(emailRecon.SPF, r)
			result(r)
		}
	}
	if len(emailRecon.SPF) == 0 {
		warn("No SPF record found — domain may be spoofable")
	}

	divider()

	// DMARC
	info("Checking DMARC record...")
	for _, r := range queryDNS("_dmarc."+domain, "TXT") {
		if strings.Contains(strings.ToLower(r), "v=dmarc1") {
			emailRecon.DMARC = r
			result(r)
			break
		}
	}
	if emailRecon.DMARC == "" {
		warn("No DMARC record found")
	}

	divider()

	// DKIM — probe multiple common selectors concurrently
	info("Checking DKIM selectors...")
	type dkimResult struct {
		selector string
		value    string
	}
	dkimCh := make(chan dkimResult, len(dkimSelectors))
	var dkimWg sync.WaitGroup
	for _, sel := range dkimSelectors {
		dkimWg.Add(1)
		go func(selector string) {
			defer dkimWg.Done()
			records := queryDNS(selector+"._domainkey."+domain, "TXT")
			if len(records) > 0 {
				dkimCh <- dkimResult{selector: selector, value: records[0]}
			}
		}(sel)
	}
	dkimWg.Wait()
	close(dkimCh)
	for r := range dkimCh {
		emailRecon.DKIM = append(emailRecon.DKIM, r.selector)
		result(fmt.Sprintf("DKIM selector found: %s", r.selector))
	}
	if len(emailRecon.DKIM) == 0 {
		warn("No DKIM selectors found")
	}

	divider()

	// BIMI (Brand Indicators for Message Identification)
	info("Checking BIMI record...")
	bimiRecords := queryDNS("default._bimi."+domain, "TXT")
	if len(bimiRecords) > 0 {
		emailRecon.BIMI = bimiRecords[0]
		result("BIMI record: " + emailRecon.BIMI)
	} else {
		result("No BIMI record found")
	}

	divider()

	// MX security analysis
	info("Checking MX records for security notes...")
	mxRecords := queryDNS(domain, "MX")
	for _, mx := range mxRecords {
		lower := strings.ToLower(mx)
		switch {
		case strings.Contains(lower, "google") || strings.Contains(lower, "googlemail"):
			emailRecon.MXSec = append(emailRecon.MXSec, "Google Workspace mail detected")
		case strings.Contains(lower, "outlook") || strings.Contains(lower, "protection.outlook"):
			emailRecon.MXSec = append(emailRecon.MXSec, "Microsoft 365 / Exchange Online detected")
		case strings.Contains(lower, "protonmail"):
			emailRecon.MXSec = append(emailRecon.MXSec, "ProtonMail detected")
		case strings.Contains(lower, "mimecast"):
			emailRecon.MXSec = append(emailRecon.MXSec, "Mimecast gateway detected")
		case strings.Contains(lower, "barracuda"):
			emailRecon.MXSec = append(emailRecon.MXSec, "Barracuda email security detected")
		}
	}
	for _, note := range emailRecon.MXSec {
		result("└─ " + note)
	}

	divider()

	// Email discovery
	info("Searching for exposed emails...")
	var allEmails []string
	for _, fn := range []func(string) []string{searchEmailsHunter, searchEmailsEmailFormat} {
		allEmails = append(allEmails, fn(domain)...)
	}
	emailRecon.Emails = dedupe(allEmails)
	if len(emailRecon.Emails) > 0 {
		info(fmt.Sprintf("Discovered %d emails:", len(emailRecon.Emails)))
		for _, email := range emailRecon.Emails[:clamp(len(emailRecon.Emails), 20)] {
			result("└─ " + email)
		}
	} else {
		result("No emails discovered from public sources")
	}

	return emailRecon
}

func searchEmailsHunter(domain string) []string {
	body, err := makeRequest(fmt.Sprintf("https://api.hunter.io/v2/domain-search?domain=%s&limit=10", domain))
	if err != nil {
		return nil
	}
	re := regexp.MustCompile(`"value"\s*:\s*"([^"]+@[^"]+)"`)
	matches := re.FindAllStringSubmatch(string(body), -1)
	var emails []string
	for _, m := range matches {
		emails = append(emails, m[1])
	}
	return dedupe(emails)
}

func searchEmailsEmailFormat(domain string) []string {
	body, err := makeRequest(fmt.Sprintf("https://www.email-format.com/%s/contact/", domain))
	if err != nil {
		return nil
	}
	re := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@` + regexp.QuoteMeta(domain))
	return dedupe(re.FindAllString(string(body), -1))
}

// ──────────────────────────────────────────────────────────────────────────────
// WAYBACK MACHINE
// ──────────────────────────────────────────────────────────────────────────────

func runWayback(domain string) []string {
	section("WAYBACK MACHINE / URL HARVEST (Passive)")
	info("Querying Wayback CDX API for historical URLs...")

	body, err := makeRequest(fmt.Sprintf(
		"https://web.archive.org/cdx/search/cdx?url=*.%s/*&output=text&fl=original&collapse=urlkey&limit=200",
		domain))
	if err != nil {
		errMsg("Wayback query failed: " + err.Error())
		return nil
	}

	var urls []string
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			urls = append(urls, line)
			if len(urls) <= 20 {
				result(line)
			}
		}
	}
	if len(urls) > 20 {
		result(fmt.Sprintf("... and %d more URLs", len(urls)-20))
	}
	success(fmt.Sprintf("Found %d historical URLs", len(urls)))
	return urls
}

// ──────────────────────────────────────────────────────────────────────────────
// GEO-IP & ASN
// ──────────────────────────────────────────────────────────────────────────────

func runGeoIP(domain string) *GeoIPInfo {
	section("GEO-IP & ASN LOOKUP (Passive)")

	aRecords := queryDNS(domain, "A")
	if len(aRecords) == 0 {
		warn("Could not resolve IP for " + domain)
		return nil
	}
	ip := aRecords[0]
	info(fmt.Sprintf("Target IP: %s", ip))

	geoInfo := &GeoIPInfo{IP: ip}

	sources := []struct {
		url string
		fn  func([]byte, *GeoIPInfo)
	}{
		{
			fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,regionName,city,isp,org,as,query", ip),
			parseIPAPI,
		},
		{
			fmt.Sprintf("https://ipapi.co/%s/json/", ip),
			parseIPAPICo,
		},
	}

	for _, src := range sources {
		body, err := makeRequest(src.url)
		if err == nil {
			src.fn(body, geoInfo)
			if geoInfo.Country != "" {
				break
			}
		}
	}

	if geoInfo.Country != "" {
		result(fmt.Sprintf("IP      : %s", geoInfo.IP))
		result(fmt.Sprintf("Country : %s", geoInfo.Country))
		result(fmt.Sprintf("Region  : %s", geoInfo.Region))
		result(fmt.Sprintf("City    : %s", geoInfo.City))
		result(fmt.Sprintf("ISP     : %s", geoInfo.ISP))
		result(fmt.Sprintf("Org     : %s", geoInfo.Org))
		result(fmt.Sprintf("ASN     : %s", geoInfo.ASN))
	} else {
		warn("Could not fetch geo info from any source")
	}

	return geoInfo
}

func parseIPAPI(body []byte, geo *GeoIPInfo) {
	var data map[string]interface{}
	if json.Unmarshal(body, &data) != nil {
		return
	}
	getString := func(key string) string {
		if v, ok := data[key].(string); ok {
			return v
		}
		return ""
	}
	geo.Country = getString("country")
	geo.Region = getString("regionName")
	geo.City = getString("city")
	geo.ISP = getString("isp")
	geo.Org = getString("org")
	geo.ASN = getString("as")
}

func parseIPAPICo(body []byte, geo *GeoIPInfo) {
	var data map[string]interface{}
	if json.Unmarshal(body, &data) != nil {
		return
	}
	getString := func(key string) string {
		if v, ok := data[key].(string); ok {
			return v
		}
		return ""
	}
	geo.Country = getString("country_name")
	geo.Region = getString("region")
	geo.City = getString("city")
	org := getString("org")
	geo.ISP = org
	geo.ASN = getString("asn")
	if geo.ASN == "" {
		geo.ASN = org
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// JSON EXPORT
// ──────────────────────────────────────────────────────────────────────────────

func collectAllSubdomains(sources []SubdomainSource) []string {
	var all []string
	for _, src := range sources {
		all = append(all, src.Subdomains...)
	}
	return dedupe(all)
}

func exportSubdomainsTxt(subdomains []string, domain string) string {
	logDir := "recon_results"
	os.MkdirAll(logDir, 0o755) //nolint:errcheck

	filename := fmt.Sprintf("%s/%s_subdomains.txt", logDir, domain)
	var sb strings.Builder
	for _, sub := range subdomains {
		sb.WriteString(sub + "\n")
	}
	os.WriteFile(filename, []byte(sb.String()), 0o644) //nolint:errcheck
	return filename
}

func exportJSON(results *ReconResults, outPath, domain string) string {
	logDir := "recon_results"
	os.MkdirAll(logDir, 0o755) //nolint:errcheck

	filename := outPath
	if filename == "" {
		timestamp := time.Now().Format("20060102_150405")
		filename = fmt.Sprintf("%s/%s_%s.json", logDir, domain, timestamp)
	}

	results.Timestamp = time.Now().Format("2006-01-02 15:04:05")
	results.AllSubdomains = collectAllSubdomains(results.Subdomains)

	jsonData, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		errMsg("Failed to marshal JSON: " + err.Error())
		return ""
	}
	if err := os.WriteFile(filename, jsonData, 0o644); err != nil {
		errMsg("Failed to write JSON file: " + err.Error())
		return ""
	}
	return filename
}

// ──────────────────────────────────────────────────────────────────────────────
// SUMMARY
// ──────────────────────────────────────────────────────────────────────────────

func printSummary(domain, jsonFile, subdomainFile string, results *ReconResults) {
	fmt.Println()
	fmt.Println(cGreen(`
 ┌──────────────────────────────────────────────────────────┐
 │                  RECONNAISSANCE COMPLETE                 │
 └──────────────────────────────────────────────────────────┘`))
	fmt.Println()
	success(fmt.Sprintf("Target      : %s", cBold(domain)))
	success(fmt.Sprintf("JSON file   : %s", cBold(jsonFile)))
	success(fmt.Sprintf("Subdomains  : %s", cBold(subdomainFile)))

	if n := len(results.AllSubdomains); n > 0 {
		success(fmt.Sprintf("Subdomains  : %d unique", n))
	}
	if n := len(results.DNSRecords); n > 0 {
		success(fmt.Sprintf("DNS records : %d types queried", n))
	}
	if results.SSLInfo != nil {
		flag := ""
		if results.SSLInfo.IsExpired {
			flag = " " + cRed("[EXPIRED]")
		} else if results.SSLInfo.ExpiresSoon {
			flag = " " + cYellow("[EXPIRING SOON]")
		}
		success(fmt.Sprintf("SSL cert    : %s (expires %s)%s",
			results.SSLInfo.Subject, results.SSLInfo.NotAfter, flag))
	}
	if results.WebInfo != nil {
		success(fmt.Sprintf("Sec headers : %d / 6", results.WebInfo.SecurityScore))
	}
	fmt.Println()
}

// ──────────────────────────────────────────────────────────────────────────────
// MAIN
// ──────────────────────────────────────────────────────────────────────────────

func main() {
	domain := flag.String("d", "", "Target domain (e.g. example.com)")
	output := flag.String("o", "", "Output JSON file path (default: recon_results/<domain>_<timestamp>.json)")
	passive := flag.Bool("passive", false, "Run only passive recon modules (skip zone transfer & web recon)")
	jsonOnly := flag.Bool("json-only", false, "Suppress terminal output, only write JSON")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("ReconX v" + version)
		os.Exit(0)
	}

	quietMode = *jsonOnly
	banner()

	if *domain == "" {
		fmt.Print(cCyan("[+] Enter the target domain (e.g. example.com): "))
		fmt.Scanln(domain)
	}

	domainStr := strings.ToLower(strings.TrimSpace(*domain))
	if domainStr == "" {
		errMsg("No domain provided. Exiting.")
		os.Exit(1)
	}

	// Strip accidental scheme prefix
	domainStr = strings.TrimPrefix(domainStr, "https://")
	domainStr = strings.TrimPrefix(domainStr, "http://")
	domainStr = strings.TrimSuffix(domainStr, "/")

	domainRe := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$`)
	if !domainRe.MatchString(domainStr) {
		warn("Domain format looks unusual, proceeding anyway...")
	}

	info(fmt.Sprintf("Target  : %s", cBold(domainStr)))
	info(fmt.Sprintf("Mode    : %s", map[bool]string{true: "Passive only", false: "Full (passive + active)"}[*passive]))
	fmt.Println()

	results := &ReconResults{Target: domainStr}

	results.DNSRecords = runDNSRecon(domainStr)
	results.Whois = runWHOIS(domainStr)
	results.EmailRecon = runEmailRecon(domainStr)
	results.SSLInfo = runSSLRecon(domainStr)
	results.GeoIP = runGeoIP(domainStr)
	results.WaybackURLs = runWayback(domainStr)
	results.Subdomains = runSubdomainEnum(domainStr)
	results.AllSubdomains = collectAllSubdomains(results.Subdomains)

	if !*passive {
		results.ZoneTransfers = runZoneTransfers(domainStr)
		results.WebInfo = runWebRecon(domainStr)
	}

	subdomainFile := exportSubdomainsTxt(results.AllSubdomains, domainStr)
	jsonFile := exportJSON(results, *output, domainStr)

	if !quietMode {
		printSummary(domainStr, jsonFile, subdomainFile, results)
	}
}
