package db

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Cond is one parsed search condition: a SQL fragment, its arguments and
// whether it is negated. Conditions are AND-ed together.
type Cond struct {
	SQL  string
	Args []any
	Neg  bool
}

// SearchError reports an invalid search query (HTTP 400 to the client).
type SearchError struct{ Msg string }

func (e *SearchError) Error() string { return e.Msg }

const maxQueryTokens = 20

// metaKeys are the search keys backed by a JSON field in events.meta.
var metaKeys = map[string]string{"ja3": "ja3", "ja4": "ja4", "sni": "sni", "user": "user"}

// columnKeys are exact-match keys on plain columns (value lower-cased).
var columnKeys = map[string]string{"kind": "kind", "class": "class", "proto": "protocol"}

// metaJSON guards json_extract: rows without meta store ” (not valid JSON).
const metaJSON = `(CASE WHEN meta = '' THEN '{}' ELSE meta END)`

var likeEsc = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// tokenize splits q on whitespace, honouring "double quoted" phrases, which
// may follow a key: (port:"80"), a leading - or stand alone.
func tokenize(q string) ([]string, error) {
	var toks []string
	var cur strings.Builder
	inQuote, has := false, false
	flush := func() {
		if has {
			toks = append(toks, cur.String())
		}
		cur.Reset()
		has = false
	}
	for _, r := range q {
		switch {
		case r == '"':
			inQuote = !inQuote
			has = true
		case unicode.IsSpace(r) && !inQuote:
			flush()
		default:
			cur.WriteRune(r)
			has = true
		}
	}
	if inQuote {
		return nil, &SearchError{"unterminated quote"}
	}
	flush()
	if len(toks) > maxQueryTokens {
		return nil, &SearchError{fmt.Sprintf("too many terms (max %d)", maxQueryTokens)}
	}
	return toks, nil
}

// ParseQuery turns the search grammar into conditions. now anchors relative
// times (since:24h).
func ParseQuery(q string, now time.Time) ([]Cond, error) {
	toks, err := tokenize(q)
	if err != nil {
		return nil, err
	}
	var conds []Cond
	for _, t := range toks {
		neg := false
		if strings.HasPrefix(t, "-") && len(t) > 1 {
			neg, t = true, t[1:]
		}
		key, val, ok := strings.Cut(t, ":")
		key = strings.ToLower(key)
		if !ok || !isKey(key) {
			if ok && isIdent(key) && !strings.ContainsAny(key, ". ") && len(key) <= 12 && val != "" && !strings.Contains(val, ":") && !strings.HasPrefix(val, "/") {
				return nil, &SearchError{fmt.Sprintf("unknown key %q", key)}
			}
			conds = append(conds, textCond(t, neg))
			continue
		}
		if val == "" {
			return nil, &SearchError{fmt.Sprintf("%s: needs a value", key)}
		}
		c, err := keyCond(key, val, now)
		if err != nil {
			return nil, err
		}
		c.Neg = neg
		conds = append(conds, c)
	}
	return conds, nil
}

func isKey(k string) bool {
	switch k {
	case "port", "ip", "cc", "asn", "tag", "scanner", "since", "until":
		return true
	}
	_, a := columnKeys[k]
	_, b := metaKeys[k]
	return a || b
}

func isIdent(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' {
			return false
		}
	}
	return true
}

func textCond(s string, neg bool) Cond {
	p := "%" + likeEsc.Replace(s) + "%"
	return Cond{
		SQL: `(detail LIKE ? ESCAPE '\' OR asn_org LIKE ? ESCAPE '\' OR src_city LIKE ? ESCAPE '\' ` +
			`OR meta LIKE ? ESCAPE '\' OR src_ip LIKE ? ESCAPE '\' OR tags LIKE ? ESCAPE '\' OR scanner LIKE ? ESCAPE '\')`,
		Args: []any{p, p, p, p, p, p, p}, Neg: neg,
	}
}

func keyCond(key, val string, now time.Time) (Cond, error) {
	switch key {
	case "port":
		n, err := strconv.Atoi(val)
		if err != nil || n < 0 || n > 65535 {
			return Cond{}, &SearchError{"port: expected 0-65535"}
		}
		return Cond{SQL: "dst_port = ?", Args: []any{n}}, nil
	case "ip":
		return Cond{SQL: `src_ip LIKE ? ESCAPE '\'`, Args: []any{likeEsc.Replace(val) + "%"}}, nil
	case "cc":
		if len(val) != 2 {
			return Cond{}, &SearchError{"cc: expected a 2-letter country code"}
		}
		return Cond{SQL: "UPPER(src_cc) = UPPER(?)", Args: []any{val}}, nil
	case "asn":
		n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(val), "AS"), 10, 32)
		if err != nil {
			return Cond{}, &SearchError{"asn: expected a number, e.g. asn:14061"}
		}
		return Cond{SQL: "asn = ?", Args: []any{n}}, nil
	case "tag":
		return Cond{SQL: `(',' || tags || ',') LIKE ? ESCAPE '\'`, Args: []any{"%," + likeEsc.Replace(val) + ",%"}}, nil
	case "scanner":
		return Cond{SQL: "LOWER(scanner) = LOWER(?)", Args: []any{val}}, nil
	case "since", "until":
		ts, err := parseTime(val, now)
		if err != nil {
			return Cond{}, &SearchError{fmt.Sprintf("%s: %v", key, err)}
		}
		op := ">="
		if key == "until" {
			op = "<="
		}
		return Cond{SQL: "time " + op + " ?", Args: []any{ts}}, nil
	}
	if col, ok := columnKeys[key]; ok {
		return Cond{SQL: col + " = ?", Args: []any{strings.ToLower(val)}}, nil
	}
	if field, ok := metaKeys[key]; ok {
		return Cond{SQL: "json_extract(" + metaJSON + ", '$." + field + "') = ?", Args: []any{val}}, nil
	}
	return Cond{}, &SearchError{fmt.Sprintf("unknown key %q", key)}
}

// parseTime accepts a relative duration (30m, 24h, 7d, 2w) or a date/time.
func parseTime(v string, now time.Time) (string, error) {
	if len(v) >= 2 {
		if n, err := strconv.Atoi(v[:len(v)-1]); err == nil && n > 0 && n <= 100000 {
			unit := map[byte]time.Duration{'m': time.Minute, 'h': time.Hour, 'd': 24 * time.Hour, 'w': 7 * 24 * time.Hour}[v[len(v)-1]]
			if unit != 0 {
				return now.Add(-time.Duration(n) * unit).UTC().Format(time.RFC3339), nil
			}
		}
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04", "2006-01-02"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC().Format(time.RFC3339), nil
		}
	}
	return "", fmt.Errorf("expected a duration like 24h/7d or a date like 2025-01-31")
}

// whereFor renders conditions into AND-ed SQL.
func whereFor(conds []Cond) (sql []string, args []any) {
	for _, c := range conds {
		s := c.SQL
		if c.Neg {
			s = "NOT (" + s + ")"
		}
		sql = append(sql, s)
		args = append(args, c.Args...)
	}
	return
}
