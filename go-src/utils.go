package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
)

var tmplCache = map[string]*template.Template{}

func expand(format string, data interface{}) (string, error) {
	name := format
	tmpl := tmplCache[name]
	var err error
	if tmpl == nil {
		if tmpl, err = template.New(name).Parse(format); err != nil {
			return "", err
		}
		tmplCache[name] = tmpl
	}
	var buf bytes.Buffer
	if err = tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

var reEOL = regexp.MustCompile(`[ \t]*\n+[ \t]*`)

func strOutput(s string) string {
	s = strings.TrimSpace(s)
	return reEOL.ReplaceAllLiteralString(s, " ... ")
}

func bufOutput(b *bytes.Buffer) string {
	return strOutput(b.String())
}

func trimColon(s string) string {
	return strings.TrimLeft(strings.TrimRight(s, ":"), ":")
}

func cutAt(s, at string) string {
	i := strings.Index(s, at)
	if i != -1 {
		s = s[:i]
	}
	return s
}

func numPartsIpv6(addr string) int {
	return strings.Count(addr, ":") + 1
}

func programName() string {
	prog, err := os.Executable()
	if (err != nil || prog == "") && len(os.Args) > 0 {
		prog = os.Args[0]
	}
	if prog == "" || prog == "-" {
		prog = "dyndns"
	}
	return filepath.Base(prog)
}
