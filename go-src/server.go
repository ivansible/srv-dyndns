package main

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var (
	webPath   string
	webUser   string
	webPass   string
	webPort   int
	webTrust  bool
	webServer *http.Server
)

func setupWebServer() error {
	webPath = paramStr("web_path", "/dyndns")
	webPath = strings.TrimRight(webPath, "/")
	webUser = paramStr("web_user", "dyndns")
	webPass = paramStr("web_pass", "")
	webPort = paramInt("web_port", "80")
	webTrust = paramInt("trust_clients", "0") != 0

	webServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", webPort),
		Handler: http.HandlerFunc(handleWebRequest),
	}
	var err error
	go func() {
		err = webServer.ListenAndServe()
	}()
	time.Sleep(time.Millisecond)
	if err != nil {
		logError("server failed: %v", err)
	}
	logDebug("server listening on port %d ...", webPort)
	return err
}

var reValidIpv4 = regexp.MustCompile(`^([0-9]{1,3}\.){3}[0-9]{1,3}$`)

func handleWebRequest(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimRight(r.URL.Path, "/")
	if r.Method != "GET" || path != webPath {
		sendError(w, "abuse", "wrong request path %q", path)
		return
	}
	user, pass, auth := r.BasicAuth()
	if !auth || user != webUser || pass != webPass {
		sendError(w, "badauth", "wrong authentication")
		return
	}

	addr := r.FormValue("myip")
	if addr == "" {
		addr = r.Header.Get("X-Real-IP")
	}
	if addr == "" {
		addr = cutAt(r.RemoteAddr, ":")
	}
	if addr != "" && !reValidIpv4.MatchString(addr) {
		sendError(w, "911", "invalid client addr %q", addr)
		return
	}

	host := r.FormValue("hostname")
	if host == "" {
		sendError(w, "nohost", "no host provided")
		return
	}
	if !strings.HasSuffix(host, "."+cfg.Domain) {
		sendError(w, "notfqdn", "invalid host %q", host)
		return
	}

	comment := "trigger"
	if webTrust {
		comment = "trusted"
	}
	logPrint("web request for %s from %s (%s)", host, addr, comment)
	if !webTrust {
		host = cfg.MainHost
		addr = ""
	}

	_, changed, err := handleRequest(host, addr, true)
	switch {
	case err != nil:
		sendError(w, "911", "update failed: %q", err)
	case changed:
		sendReply(w, "good")
	default:
		sendReply(w, "nochg")
	}
}

func sendReply(w http.ResponseWriter, reply string) {
	if _, err := io.WriteString(w, reply); err != nil {
		logPrint("failed to send reply: %v", err)
	}
}

func sendError(w http.ResponseWriter, reply string, msg string, args ...interface{}) {
	sendReply(w, reply)
	logPrint("web: "+msg, args...)
}
