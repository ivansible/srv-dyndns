// +build !windows

package main

import (
	"os/user"
	"strconv"

	"golang.org/x/sys/unix"
)

func dropPrivileges() error {
	if unix.Getuid() != 0 {
		return nil
	}

	nobody, err := user.Lookup("nobody")
	if err != nil {
		return err
	}
	uidNobody, err := strconv.Atoi(nobody.Uid)
	if err != nil {
		return err
	}

	nogroup, err := user.LookupGroup("nogroup")
	if err != nil {
		return err
	}
	gidNogroup, err := strconv.Atoi(nogroup.Gid)
	if err != nil {
		return err
	}

	if err == nil {
		err = unix.Setgroups([]int{})
	}
	if err == nil {
		err = unix.Setgid(gidNogroup)
	}
	if err == nil {
		err = unix.Setuid(uidNobody)
	}
	return err
}
