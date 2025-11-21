//go:build windows

package network

import (
	"fmt"
	"os/exec"
	"strconv"
)

func (iface *TunInterface) setUpInterface() error {
	// Set MTU
	cmd := exec.Command("netsh", "interface", "ipv6", "set", "interface", "interface=\""+iface.name+"\"",
		"mtu="+strconv.Itoa(iface.mtu))
	output, err := cmd.CombinedOutput()
	if err != nil {
		iface.logger.Info("netsh", "output", output, "err", err)
		return err
	}

	for _, cidr := range iface.cidrs {
		var cmd *exec.Cmd
		if cidr.IP.Is4() {
			mask := cidr.Network.Mask
			maskStr := fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
			iface.logger.Info("set TUN", "IPv4", cidr.IP.String(), "Netmask", maskStr)
			cmd = exec.Command("netsh", "interface", "ip", "set", "address",
				fmt.Sprintf("name=\"%s\"", iface.name),
				"static",
				cidr.IP.String(),
				maskStr)
			output, err := cmd.CombinedOutput()
			if err != nil {
				iface.logger.Error("netsh set ip", "output", output, "err", err)
				return err
			}
		} else {
			maskSize, _ := cidr.Network.Mask.Size()
			addrStr := cidr.IP.String() + "/" + strconv.Itoa(maskSize)
			iface.logger.Info("set TUN", "IPv6", addrStr)
			cmd = exec.Command("netsh", "interface", "ipv6", "add", "address",
				fmt.Sprintf("interface=\"%s\"", iface.name),
				"address="+addrStr)
			iface.logger.Info("netsh", "cmd", cmd.String())
			output, err = cmd.CombinedOutput()
			if err != nil {
				iface.logger.Error("netsh set ipv6", "output", output, "err", err)
				return err
			}

			// Windows requeres explicit route for IPv6 nets
			iface.logger.Info("set IPv6 route", "net", cidr.Network.String())
			cmd = exec.Command("netsh", "interface", "ipv6", "add", "route",
				cidr.Network.String(), "iterface=\""+iface.name+"\"")
			output, err = cmd.CombinedOutput()
			if err != nil {
				iface.logger.Error("netsh add route", "output", output, "err", err)
				return err
			}
		}
	}
	return nil
}
