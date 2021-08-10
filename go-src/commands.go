package main

import (
	"bytes"
	"os/exec"
	"strings"
	"sync"

	"github.com/google/shlex"
	"github.com/pkg/errors"
)

var (
	nodeHosts []*sshConn
	mainCmd   string
	nodeCmd   string
)

func setupCommands() error {
	for _, url := range paramList("node_hosts", "") {
		conn, err := newSSHConn(url)
		if err != nil {
			return err
		}
		nodeHosts = append(nodeHosts, conn)
		logDebug("added node %q", url)
	}
	logDebug("got %d node hosts (will run locally if none)", len(nodeHosts))

	nodeCmd = paramStr("node_cmd", "")
	mainCmd = paramStr("main_cmd", "")
	logDebug("node_cmd:%q main_cmd:%q", nodeCmd, mainCmd)
	return nil
}

func runCommands(ipv4, ipv6 string) (err error) {
	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		runErr := runCmd("node_cmd", nodeCmd, ipv4, ipv6, nodeHosts...)
		if err == nil && runErr != nil {
			err = runErr
		}
		wg.Done()
	}()
	go func() {
		runErr := runCmd("main_cmd", mainCmd, ipv4, ipv6, probeConn)
		if err == nil && runErr != nil {
			err = runErr
		}
		wg.Done()
	}()
	wg.Wait()
	return
}

func runCmd(name, cmd, ipv4, ipv6 string, hosts ...*sshConn) (err error) {
	if cmd == "" {
		return
	}
	if ipv4 == "-" || ipv4 == "" {
		ipv4 = "127.0.0.1"
	}
	if ipv6 == "-" || ipv6 == "" {
		ipv6 = "::1"
	}
	cmd = strings.ReplaceAll(cmd, "{ipv4}", ipv4)
	cmd = strings.ReplaceAll(cmd, "{ipv6}", ipv6)

	if len(hosts) == 0 {
		return runLocally(name, cmd)
	}

	wg := sync.WaitGroup{}
	wg.Add(len(hosts))
	for _, conn := range hosts {
		go func(conn *sshConn) {
			defer wg.Done()
			outStr, errStr, runErr := conn.execute(cmd)
			switch {
			case runErr != nil:
				logError("%s[%s]: ssh failed: %v", name, conn.host, err)
				if err == nil {
					err = runErr
				}
			case errStr != "":
				logError("%s[%s] failed: %s", name, conn.host, errStr)
			case outStr != "":
				logPrint("%s[%s] output: %q", name, conn.host, outStr)
			}
		}(conn)
	}
	wg.Wait()
	return
}

func runLocally(name, cmd string) error {
	args, err := shlex.Split(cmd)
	if err != nil {
		logError("%s[local] failed to parse %q: %q", name, cmd, err)
		return err
	}
	proc := exec.Command(args[0], args[1:]...)
	outBuf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	proc.Stdout = outBuf
	proc.Stderr = errBuf
	err = proc.Run()
	exitCode := -1
	if err == nil {
		exitCode = proc.ProcessState.ExitCode()
	}
	outStr := bufOutput(outBuf)
	errStr := bufOutput(errBuf)
	switch {
	case err != nil:
		logError("%s[local] failed to run: %q", name, err)
	case exitCode != 0 || errStr != "":
		if errStr == "" {
			errStr = "-"
		}
		logError("%s[local] failed with code %d: %q", name, exitCode, errStr)
		err = errors.Errorf("local command failed: %s", errStr)
	case outStr != "":
		logPrint("%s[local] output: %q", name, outStr)
	default:
		logDebug("%s[local] cmd %q output: %q", name, args, outStr)
	}
	return err
}
