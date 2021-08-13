package main

import (
	"context"
	"strings"

	"github.com/cloudflare/cloudflare-go"
	"github.com/pkg/errors"
)

var (
	api    *cloudflare.API
	zoneID string
)

func setupCloudflare() (err error) {
	if api != nil && zoneID != "" {
		return nil
	}
	domain := cfg.Domain
	email := paramStr("cloudflare_email", Required)
	token := paramStr("cloudflare_token", Required)
	api, err = cloudflare.New(token, email)
	if err != nil {
		return errors.Wrap(err, "failed to setup cloudflare")
	}
	zoneID, err = api.ZoneIDByName(domain)
	if err != nil {
		return errors.Wrapf(err, "cloudflare zone not found: %s", domain)
	}
	return nil
}

func updateHost(host, addr string, ipv6 bool) (bool, error) {
	if api == nil || zoneID == "" {
		if err := setupCloudflare(); err != nil {
			return false, errors.Wrap(err, "cloudflare setup failed")
		}
	}

	if host == "" || addr == "" {
		return false, nil
	}

	name := strings.TrimSuffix(host, "."+cfg.Domain)
	if name == host {
		logError("host %s not in zone %s", host, cfg.Domain)
		return false, errors.New("host not in zone")
	}
	if name == "" {
		logError("host without name: %s", host)
		return false, errors.New("host without name")
	}

	rtype := "A"
	if ipv6 {
		rtype = "AAAA"
	}
	proxyFlag := false
	record := cloudflare.DNSRecord{
		Name:    host,
		Type:    rtype,
		Content: addr,
		Proxied: &proxyFlag,
	}

	filter := cloudflare.DNSRecord{
		Name: host,
		Type: rtype,
	}
	ctx := context.Background()
	records, err := api.DNSRecords(ctx, zoneID, filter)
	if err != nil {
		return false, errors.Wrap(err, "failed to list zone")
	}

	found := false
	changed := false
	for _, r := range records {
		if r.Type != rtype {
			continue
		}
		found = true

		proxied := false
		if r.Proxied != nil {
			proxied = *r.Proxied
		}
		if r.Content == addr && proxied == proxyFlag {
			logDebug("keep %s as %s (%s)", host, addr, rtype)
			continue
		}

		if addr != "-" {
			logPrint("update %s as %s (%s)", host, addr, rtype)
			if err = api.UpdateDNSRecord(ctx, zoneID, r.ID, record); err != nil {
				return false, errors.Wrap(err, "failed to update DNS record")
			}
		} else {
			logPrint("delete %s as %s", host, rtype)
			if err = api.DeleteDNSRecord(ctx, zoneID, r.ID); err != nil {
				return false, errors.Wrap(err, "failed to delete DNS record")
			}
		}
		changed = true
	}

	if !found && addr != "-" {
		logPrint("create %s as %s (%s)", host, addr, rtype)
		if _, err = api.CreateDNSRecord(ctx, zoneID, record); err != nil {
			return false, errors.Wrap(err, "failed to create DNS record")
		}
		changed = true
	}

	return changed, nil
}
