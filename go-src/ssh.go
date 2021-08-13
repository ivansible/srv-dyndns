package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/url"
	"os/user"
	"strings"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

type sshConn struct {
	url  string
	host string
	user string
	pass string
	key  string
}

func newSSHConn(urlStr string) (*sshConn, error) {
	if urlStr == "" {
		return nil, nil
	}

	if !strings.Contains(urlStr, "://") {
		urlStr = "ssh://" + urlStr
	}
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot parse ssh url: %q", urlStr)
	}

	c := &sshConn{
		host: u.Host,
	}
	if !strings.Contains(c.host, ":") {
		c.host = fmt.Sprintf("%s:%d", c.host, 22)
	}

	if u.User != nil {
		c.user = u.User.Username()
		if password, ok := u.User.Password(); ok {
			c.pass = password
		}
	}
	if c.user == "" {
		return nil, errors.Errorf("user missing in ssh url: %q", urlStr)
	}

	q := u.Query()
	keyFile := strings.TrimSpace(q.Get("keyfile"))
	c.key = strings.ReplaceAll(strings.TrimSpace(q.Get("keystr")), ",", "\n")
	if keyFile == "" && c.key == "" {
		keyFile = strings.TrimSpace(q.Get("key"))
	}

	if strings.HasPrefix(keyFile, "~") {
		homeDir := "/root"
		if usr, err := user.Current(); err == nil {
			homeDir = usr.HomeDir
		}
		keyFile = strings.Replace(keyFile, "~", homeDir, 1)
	}
	if keyFile != "" {
		keyData, err := ioutil.ReadFile(keyFile)
		if err != nil {
			return nil, errors.Wrapf(err, "unable to read private key: %s", keyFile)
		}
		c.key = string(keyData)
	}
	if c.key != "" {
		_, err := ssh.ParsePrivateKey([]byte(c.key))
		if err != nil {
			return nil, errors.Wrapf(err, "unable to parse private key: %q", c.key)
		}
	}

	u.User = nil
	u.RawQuery = ""
	c.url = u.String()
	return c, nil
}

func (c *sshConn) connect() (*ssh.Client, error) {
	auth := []ssh.AuthMethod{}
	if c.key != "" {
		signer, err := ssh.ParsePrivateKey([]byte(c.key))
		if err != nil {
			return nil, errors.Wrapf(err, "unable to parse private key: %q", c.key)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if c.pass != "" {
		auth = append(auth, ssh.Password(c.pass))
	}

	conf := &ssh.ClientConfig{
		User:            c.user,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         cfg.Timeout,
	}

	var (
		cli   *ssh.Client
		retry int
		err   error
	)
	for {
		cli, err = ssh.Dial("tcp", c.host, conf)
		if err == nil {
			return cli, nil
		}
		retry++
		if retry >= cfg.RetryCount {
			break
		}
		logError("retry ssh login #%d: %s", retry, c.url)
		time.Sleep(cfg.RetrySleep)
	}
	return nil, errors.Wrapf(err, "ssh login failed: %s", c.url)
}

func (c *sshConn) execute(cmd string) (string, string, error) {
	cli, err := c.connect()
	if err != nil {
		return "", "", err
	}
	defer cli.Close()

	sess, err := cli.NewSession()
	if err != nil {
		return "", "", errors.Wrap(err, "failed to create session")
	}
	defer sess.Close()

	outBuf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	sess.Stdout = outBuf
	sess.Stderr = errBuf
	err = sess.Run(cmd)
	cmdStr := strOutput(cmd)
	outStr := bufOutput(outBuf)
	errStr := bufOutput(errBuf)
	logDebug(`ssh: host:%q cmd:%q stdout:%q stderr:%q err:%v`,
		c.host, cmdStr, outStr, errStr, err)
	return outStr, errStr, err
}
