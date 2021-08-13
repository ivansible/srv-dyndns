package main

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"gopkg.in/ini.v1"
)

const (
	ConfigFile = "/etc/dyndns.conf"
	ConfigSect = "dyndns"
	Required   = "!REQUIRED!"
)

var (
	cfgSect  *ini.Section
	cfgCache = map[string]string{}
)

func setupConfig() error {
	if cfgSect != nil {
		return nil
	}
	cfgPath := os.Getenv("DYNDNS_CONFIG_FILE")
	if cfgPath == "" {
		cfgPath = ConfigFile
	}
	opts := ini.LoadOptions{
		AllowPythonMultilineValues: true,
		IgnoreInlineComment:        true,
	}
	cfgFile, err := ini.LoadSources(opts, cfgPath)
	if err != nil {
		return errors.Wrapf(err, "failed to read config: %s", cfgPath)
	}
	sect, err := cfgFile.GetSection(ConfigSect)
	if err != nil {
		return errors.Wrapf(err, "missing config section [%s]: %s", ConfigSect, cfgPath)
	}
	cfgSect = sect
	return nil
}

func paramStr(name string, def string) string {
	if val, ok := cfgCache[name]; ok {
		return val
	}
	if cfgSect == nil {
		logFatal("config file not ready for value: %s", name)
	}
	if def != Required && !cfgSect.HasKey(name) {
		return def
	}
	key, err := cfgSect.GetKey(name)
	if err != nil {
		logFatal("failed to read config value: %s", name)
	}
	val := strings.TrimSpace(key.String())
	cfgCache[name] = val
	return val
}

func paramInt(name string, def string) int {
	str := paramStr(name, def)
	val, err := strconv.Atoi(str)
	if err != nil {
		logFatal("failed to read config value: %s", name)
	}
	return val
}

func paramSeconds(name string, def string) time.Duration {
	return time.Duration(paramInt(name, def)) * time.Second
}

func paramList(name string, def string) (list []string) {
	delimiter := regexp.MustCompile(`[,\s]+`)
	listVal := paramStr(name, def)
	for _, val := range delimiter.Split(listVal, -1) {
		val = strings.TrimSpace(val)
		if val != "" {
			list = append(list, val)
		}
	}
	return
}
