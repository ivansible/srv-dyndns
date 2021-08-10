package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
)

var cfg struct {
	Verbose      int
	TestHandlers bool

	PrefixLen   int
	PrefixDev   string
	ProviderDev string

	RetrySleep   time.Duration
	RetryCount   int
	RetryExpon   int
	PollInterval time.Duration
	Timeout      time.Duration

	MainHost string
	Domain   string
}

func main() {
	var mode string
	switch len(os.Args) {
	case 1:
		mode = "service"
	case 2:
		mode = os.Args[1]
	default:
		mode = "help"
	}
	switch mode {
	case "update", "web", "poll", "service":
		// OK
	default:
		fmt.Printf("usage: %s service|web|poll|update\n", programName())
		os.Exit(1)
	}

	ctx := context.Background()
	runOnce := false
	webActive := false
	pollActive := false

	switch mode {
	case "update":
		runOnce = true
	case "web":
		webActive = true
	case "poll":
		pollActive = true
	case "service":
		pollActive = true
		webActive = true
	}

	if err := setupAll(ctx, webActive); err != nil {
		logFatal("setup failed: %v", err)
	}

	if runOnce {
		if err := updateOnce(); err != nil {
			logError("update failed: %v", err)
		}
		return
	}

	if err := dropPrivileges(); err != nil {
		logFatal("cannot drop privileges: %v", err)
	}

	if pollActive {
		pollService()
	}
}

func updateOnce() error {
	res, changed, err := handleRequest(cfg.MainHost, "", false)
	if err != nil {
		return err
	}

	probeChanged := false
	if res.ipv4 == "" || res.ipv6 == "" || res.pfx6 == "" {
		res, probeChanged, err = probeAddr()
		if err != nil {
			return err
		}
	}

	if changed || probeChanged {
		ipv6 := res.ipv6
		if res.pfx6 != "" {
			ipv6 = res.pfx6
		}
		if err = runCommands(res.ipv4, ipv6); err != nil {
			return err
		}
	}

	// abbreviate NATed address for debugging
	if res.if4 == "" {
		res.if4 = "-"
	}
	if res.if4 == res.ipv4 {
		res.if4 = "+"
	}
	logDebug("ipv4 %q ipv6 %q pfx6 %q if4 %q",
		res.ipv4, res.ipv6, res.pfx6, res.if4)
	return nil
}

func pollService() {
	if cfg.PollInterval <= 0 {
		logPrint("poll disabled")
		return
	}
	time.Sleep(time.Millisecond)

	retrySleep := cfg.RetrySleep
	retryCount := 0
	for {
		if retryCount == 0 {
			logPrint("next poll")
		}
		err := updateOnce()
		if cfg.TestHandlers {
			err = errors.New("test error")
		}
		if err == nil {
			logDebug("poll sleeping for %v", cfg.PollInterval)
			time.Sleep(cfg.PollInterval)
			retrySleep = cfg.RetrySleep
			retryCount = 0
			continue
		}

		retryCount++
		logPrint("poll retry #%d sleep %v error: %q", retryCount, retrySleep, err)
		time.Sleep(retrySleep)
		retrySleep *= time.Duration(cfg.RetryExpon)
		if retrySleep > cfg.PollInterval {
			retrySleep = cfg.PollInterval
		}
	}
}

func handleRequest(host, addr string, viaWeb bool) (res *result, changed bool, err error) {
	ipv4 := ""
	ipv6 := ""
	if strings.Contains(addr, ":") {
		ipv6 = addr
	} else {
		ipv4 = addr
	}

	if4 := ipv4
	pfx6 := ""
	pfxChanged := false
	if host == cfg.MainHost {
		var probe *result
		probe, pfxChanged, err = probeAddr()
		if err != nil {
			return
		}
		if ipv4 == "" {
			ipv4 = probe.ipv4
		}
		if ipv6 == "" {
			ipv6 = probe.ipv6
		}
		pfx6 = probe.pfx6
		if4 = probe.if4
	}

	res = &result{
		ipv4: ipv4,
		ipv6: ipv6,
		pfx6: pfx6,
	}

	if strings.HasPrefix(if4, "10.") {
		logPrint("ignore NATed address %s", ipv4)
		ipv4 = "-"
	}

	ipv4Changed, err2 := updateHost(host, ipv4, false)
	if err == nil {
		err = err2
	}
	ipv6Changed, err2 := updateHost(host, ipv6, true)
	if err == nil {
		err = err2
	}
	changed = ipv4Changed || ipv6Changed || pfxChanged || cfg.TestHandlers

	if host == cfg.MainHost && changed && viaWeb {
		if pfx6 != "" {
			ipv6 = pfx6
		}
		err2 := runCommands(ipv4, ipv6)
		if err == nil {
			err = err2
		}
	}

	return
}

func setupAll(ctx context.Context, webActive bool) error {
	if err := setupConfig(); err != nil {
		return err
	}

	cfg.Verbose = paramInt("verbose", "0")
	cfg.TestHandlers = paramInt("test_handlers", "0") != 0

	cfg.RetrySleep = paramSeconds("retry_sleep", "30")
	cfg.RetryCount = paramInt("retry_count", "3")
	cfg.RetryExpon = paramInt("retry_expon", "2")
	cfg.PollInterval = paramSeconds("poll_interval", "3600")
	cfg.Timeout = paramSeconds("timeout", "5")

	cfg.Domain = paramStr("domain", "")
	mainHost := paramStr("main_host", "")
	if strings.Contains(mainHost, ".") {
		return errors.Errorf("hostname %q must not be fully qualified", mainHost)
	}
	if mainHost != "" {
		cfg.MainHost = fmt.Sprintf("%s.%s", mainHost, cfg.Domain)
	}

	if err := setupProber(); err != nil {
		return err
	}
	if err := setupCommands(); err != nil {
		return err
	}
	if err := setupCloudflare(ctx, cfg.Domain); err != nil {
		return err
	}

	if webActive {
		if err := setupWebServer(); err != nil {
			return err
		}
	}

	return nil
}
