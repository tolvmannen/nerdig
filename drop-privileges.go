package main

import (
	"log"
	"os/user"
	"strconv"
	"syscall"
)

func dropPrivileges(userToSwitchTo string) {

	// Lookup user and group IDs for the user we want to switch to.
	userInfo, err := user.Lookup(userToSwitchTo)
	if err != nil {
		log.Fatal(err)
	}
	// Convert group ID and user ID from string to int.
	gid, err := strconv.Atoi(userInfo.Gid)
	if err != nil {
		log.Fatal(err)
	}
	uid, err := strconv.Atoi(userInfo.Uid)
	if err != nil {
		log.Fatal(err)
	}
	// Unset supplementary group IDs.
	err = syscall.Setgroups([]int{})
	if err != nil {
		log.Fatal("Failed to unset supplementary group IDs: " + err.Error())
	}
	// Set group ID (real and effective).
	err = syscall.Setgid(gid)
	if err != nil {
		log.Fatal("Failed to set group ID: " + err.Error())
	}
	// Set user ID (real and effective).
	err = syscall.Setuid(uid)
	if err != nil {
		log.Fatal("Failed to set user ID: " + err.Error())
	}

}

// NOTE: https://stackoverflow.com/questions/41248866/golang-dropping-privileges-v1-7
