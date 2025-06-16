package common

import (
	"errors"
	"net"
)

var ErrNoLocalIP = errors.New("dialing local IP addresses is not allowed")

func IsLocalIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() {
		return true
	}

	return false
}
