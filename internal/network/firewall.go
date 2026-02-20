package network

import (
	"fmt"
	"os/exec"

	"github.com/sem-hub/snake-net/internal/configs"
)

func OpenFirewallPort(port uint16, protocol string) error {
	logger := configs.InitLogger("firewall")
	logger.Info("Opening firewall port", "port", port)
	name := ""
	if protocol == "datagram" {
		name = "udp"
	} else {
		name = "tcp"
	}
	cmd := exec.Command("iptables", "-I", "INPUT", "-p", name, "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT")
	if err := cmd.Run(); err != nil {
		logger.Error("Error:" + err.Error())
		logger.Debug("Command:", "cmd", cmd.String())
		return err
	}
	cmd = exec.Command("ip6tables", "-I", "INPUT", "-p", name, "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT")
	if err := cmd.Run(); err != nil {
		logger.Error("Error:" + err.Error())
		logger.Debug("Command:", "cmd", cmd.String())
		return err
	}
	return nil
}

func CloseFirewallPort(port uint16, protocol string) error {
	logger := configs.InitLogger("firewall")
	logger.Info("Closing firewall port", "port", port)
	name := ""
	if protocol == "datagram" {
		name = "udp"
	} else {
		name = "tcp"
	}
	cmd := exec.Command("iptables", "-D", "INPUT", "-p", name, "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT")
	if err := cmd.Run(); err != nil {
		logger.Error("Error:" + err.Error())
		logger.Debug("Command:", "cmd", cmd.String())
		return err
	}
	cmd = exec.Command("ip6tables", "-D", "INPUT", "-p", name, "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT")
	if err := cmd.Run(); err != nil {
		logger.Error("Error:" + err.Error())
		logger.Debug("Command:", "cmd", cmd.String())
		return err
	}
	return nil
}
