package services

import (
	"regexp"
	"sort"
	"strings"
)

// signature maps a payload pattern to a tag. Patterns are matched
// case-insensitively against the raw request / command text.
type signature struct {
	tag string
	re  *regexp.Regexp
}

func sig(tag, pattern string) signature {
	return signature{tag: tag, re: regexp.MustCompile(`(?i)` + pattern)}
}

var payloadSignatures = []signature{
	sig("log4shell", `\$\{\s*(jndi|lower|upper|env|::-)`),
	sig("path-traversal", `(\.\./|\.\.\\|%2e%2e[/%\\]|%252e%252e)`),
	sig("env-probe", `/\.(env|git/|aws/|ssh/|svn/|docker|htpasswd|DS_Store)|/(config|settings|secrets?)\.(json|ya?ml|php\.bak)`),
	sig("wordpress-probe", `/(wp-login|wp-admin|wp-content|wp-includes|xmlrpc)\.?`),
	sig("admin-panel-probe", `/(phpmyadmin|pma|adminer|manager/html|admin/login|console|actuator|solr/admin|jenkins|grafana/login)`),
	sig("shell-injection", `(;|\||&&|\x60|\$\()\s*(wget|curl|tftp|busybox|nc|ncat|bash|sh|chmod|rm)\b|/bin/(ba)?sh`),
	sig("sqli", `(union(\s|%20|\+)+(all(\s|%20|\+)+)?select|or(\s|%20|\+)+1(\s|%20|\+)*=(\s|%20|\+)*1|sleep\(\d|information_schema)`),
	sig("xss", `<script|javascript:|onerror\s*=`),
	sig("php-rce", `(php://input|allow_url_include|auto_prepend_file|eval-stdin\.php|/vendor/phpunit|think\\app/invokefunction|/index\.php\?s=)`),
	sig("router-exploit", `/(boaform|GponForm|cgi-bin/(luci|admin)|setup\.cgi|HNAP1|tmUnblock\.cgi|goform/|shell\?cmd|login\.cgi|ping\.cgi|apply\.cgi)`),
	sig("cgi-bin-probe", `/cgi-bin/`),
	sig("spring4shell", `class\.module\.classLoader|spring\.cloud\.function\.routing-expression`),
	sig("struts-ognl", `%\{|\$\{#`),
	sig("proxy-probe", `^(connect|get)\s+(https?://|[\w.-]+:\d+)`),
	sig("docker-api-probe", `/(v\d\.\d+/)?(containers|images)/json|/version$`),
	sig("redis-exploit", `\b(config\s+set|slaveof|replicaof|module\s+load|eval|flushall|script\s+load)\b`),
	sig("sip-scan", `^(options|register|invite)\s+sip:|friendly-scanner|sipvicious`),
	sig("ssdp-scan", `m-search|ssdp:discover`),
	sig("mirai-like", `/bin/busybox|MIRAI|/tmp/\.|chmod\s+777`),
}

// uaSignatures identify well-known scanner software and research crawlers.
var uaSignatures = []signature{
	sig("scanner:zgrab", `zgrab`),
	sig("scanner:masscan", `masscan`),
	sig("scanner:nmap", `nmap`),
	sig("scanner:censys", `censys`),
	sig("scanner:shodan", `shodan`),
	sig("scanner:expanse", `expanse|palo alto networks`),
	sig("scanner:internet-measurement", `internet-?measurement|research|scan(ner)?\b|netcraft|binaryedge|leakix|onyphe|stretchoid`),
	sig("scanner:nuclei", `nuclei|projectdiscovery`),
	sig("scanner:sqlmap", `sqlmap`),
	sig("scanner:nikto", `nikto`),
	sig("scanner:go-http", `^go-http-client`),
	sig("scanner:python-requests", `^python-requests|^python-urllib|^aiohttp`),
	sig("scanner:curl", `^curl/|^wget/`),
}

// Classify returns the sorted, de-duplicated tags matching a payload and,
// optionally, a User-Agent string.
func Classify(payload, userAgent string) []string {
	set := map[string]struct{}{}
	for _, s := range payloadSignatures {
		if s.re.MatchString(payload) {
			set[s.tag] = struct{}{}
		}
	}
	if userAgent != "" {
		for _, s := range uaSignatures {
			if s.re.MatchString(userAgent) {
				set[s.tag] = struct{}{}
			}
		}
	}
	if len(set) == 0 {
		return nil
	}
	tags := make([]string, 0, len(set))
	for t := range set {
		tags = append(tags, t)
	}
	sort.Strings(tags)
	return tags
}

// miraiCreds is a sample of default credentials hard-coded in Mirai-family
// botnets; a login attempt using one is tagged accordingly.
var miraiCreds = map[string]struct{}{
	"root:xc3511": {}, "root:vizxv": {}, "root:admin": {}, "admin:admin": {}, "root:888888": {},
	"root:xmhdipc": {}, "root:default": {}, "root:juantech": {}, "root:123456": {}, "root:54321": {},
	"support:support": {}, "root:": {}, "admin:password": {}, "root:root": {}, "root:12345": {},
	"user:user": {}, "admin:": {}, "root:pass": {}, "admin:1234": {}, "admin:12345": {},
	"root:klv123": {}, "root:hi3518": {}, "root:ikwb": {}, "root:realtek": {}, "root:7ujMko0admin": {},
	"admin:smcadmin": {}, "root:Zte521": {}, "root:zlxx.": {}, "guest:12345": {}, "admin1:password": {},
}

// ClassifyCreds tags a login attempt.
func ClassifyCreds(user, pass string) []string {
	var tags []string
	if _, ok := miraiCreds[user+":"+pass]; ok {
		tags = append(tags, "mirai-default-creds")
	}
	if strings.EqualFold(user, "root") || strings.EqualFold(user, "admin") {
		tags = append(tags, "privileged-user")
	}
	return tags
}

func mergeTags(sets ...[]string) []string {
	set := map[string]struct{}{}
	for _, s := range sets {
		for _, t := range s {
			set[t] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
