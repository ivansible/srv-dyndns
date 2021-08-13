package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
)

func expand(format string, data interface{}) (string, error) {
	name := format
	tmpl, err := template.New(name).Parse(format)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	err = tmpl.Execute(&buf, data)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func strOutput(s string) string {
	s = strings.TrimSpace(s)
	reEOL := regexp.MustCompile(`[ \t]*\n+[ \t]*`)
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
