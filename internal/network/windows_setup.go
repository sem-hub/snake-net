//go:build windows

package network

import (
	"fmt"
	"os/exec"
	"strconv"
)

func (iface *TunInterface) setUpInterface() error {
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
		} else {
			maskSize, _ := cidr.Network.Mask.Size()
			maskStr := strconv.Itoa(maskSize)
			iface.logger.Info("set TUN", "IPv6", cidr.IP.String(), "Prefixlen", maskStr)
			cmd = exec.Command("netsh", "interface", "ipv6", "set", "address",
				fmt.Sprintf("interface=\"%s\"", iface.name),
				"address="+cidr.IP.String(),
				"prefixlen="+maskStr)
		}

		output, err := cmd.CombinedOutput()
		if err != nil {
			iface.logger.Error("netsh", "output", output, "err", err)
		}
	}
	return nil

}
