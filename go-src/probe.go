package main

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/pkg/errors"
)

type result struct {
	ipv4 string
	ipv6 string
	pfx6 string
	if4  string
}

var (
	probeConn   *sshConn
	probeCmd    string
	prefixHosts = map[string]string{}
)

const ProbeCmd = `#!/bin/sh
#set -x
PATH=/opt/sbin:/opt/bin
prefix_len={{.PrefixLen}}
prefix_dev={{.PrefixDev}}
provider_dev={{.ProviderDev}}
[ -f /opt/etc/net/config ] && . /opt/etc/net/config
ipv4=$(curl -4sk https://ipv4.icanhazip.com)
ipv6=$(curl -6sk https://ipv6.icanhazip.com)
pfx6=$(ip -o -6 route show dev ${prefix_dev} |
       awk "/:\/${prefix_len}/ && !/^ff00|^fe80/ {print \$1; exit}")
if4=$(ip -o -4 addr show dev ${provider_dev} | awk "{print \$4; exit}")
echo "ipv4=${ipv4} ipv6=${ipv6} pfx6=${pfx6} if4=${if4}"
`

func probeAddr() (*result, bool, error) {
	reProbe := regexp.MustCompile(`^ipv4=([0-9.]*) ipv6=([0-9a-f:]*) pfx6=([0-9a-f:/]*) if4=([0-9./]*)$`)

	outStr, errStr, err := probeConn.execute(probeCmd)
	if err != nil {
		return nil, false, err
	}

	match := reProbe.FindStringSubmatch(outStr)
	if match == nil {
		logError("address probe failed: %s", errStr)
		return nil, false, errors.New("address probe failed")
	}
	probe := &result{
		ipv4: match[1],
		ipv6: match[2],
	}

	prefix := match[3]
	var (
		fullPrefix string
		purePrefix string
	)
	if strings.Contains(prefix, "/") {
		fullPrefix = prefix
		purePrefix = trimColon(cutAt(prefix, "/"))
	} else {
		purePrefix = trimColon(prefix)
		fullPrefix = purePrefix
		if !strings.Contains(fullPrefix, "::") {
			fullPrefix += "::"
		}

		prefixLen := cfg.PrefixLen
		if prefixLen == 0 {
			prefixLen = 64
		}
		fullPrefix += fmt.Sprintf("/%d", prefixLen)
	}

	if strings.Contains(purePrefix, "::") {
		purePrefix = trimColon(cutAt(prefix, "::"))
	}
	prefixParts := numPartsIpv6(purePrefix)

	probe.pfx6 = fullPrefix
	probe.if4 = cutAt(match[4], "/") // ipv4 assigned on provider interface

	changeCount := 0
	for host, addr := range prefixHosts {
		fullHost := fmt.Sprintf("%s.%s", host, cfg.Domain)
		addrParts := numPartsIpv6(trimColon(addr))
		if prefixParts+addrParts > 8 {
			logError("invalid addr %q for prefix %q", addr, prefix)
			continue
		}

		delimiter := ":"
		if prefixParts+addrParts < 8 {
			delimiter = "::"
		}
		fullAddr := purePrefix + delimiter + addr

		changed, _ := updateHost(fullHost, fullAddr, true)
		if changed {
			changeCount++
		}
	}

	logPrint("%d of %d hosts updated for prefix %s", changeCount, len(prefixHosts), prefix)
	return probe, changeCount > 0, nil
}

func setupProber() error {
	var err error
	probeConn, err = newSSHConn(paramStr("ssh_url", ""))
	if err != nil {
		return err
	}

	cfg.PrefixLen = paramInt("prefix_len", "0")
	cfg.PrefixDev = paramStr("prefix_dev", "")
	cfg.ProviderDev = paramStr("provider_dev", "")

	reValidIpv6 := regexp.MustCompile(`^[0-9a-f][0-9a-f:]+[0-9a-f]$`)

	for _, item := range paramList("prefix_hosts", "") {
		tokens := strings.Split(item, "=")
		if len(tokens) != 2 {
			return errors.Errorf("invalid prefix host: %q", item)
		}
		host := strings.TrimSpace(tokens[0])
		if strings.Contains(host, ".") {
			return errors.Errorf("invalid prefix host name: %q", host)
		}
		addr := strings.ToLower(strings.TrimSpace(tokens[1]))
		if !reValidIpv6.MatchString(addr) {
			return errors.Errorf("invalid prefix host address: %q", addr)
		}
		addr = strings.TrimLeft(strings.TrimRight(addr, ":"), ":")
		if host == "" || addr == "" {
			return errors.Errorf("invalid prefix host: %q", item)
		}
		prefixHosts[host] = addr
	}

	probeCmd = paramStr("probe_cmd", ProbeCmd)
	if probeCmd, err = expand(probeCmd, cfg); err != nil {
		return err
	}
	logDebug("probe cmd: %q", strOutput(probeCmd))
	return nil
}
