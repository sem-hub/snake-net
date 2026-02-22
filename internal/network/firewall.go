package network

import (
	"fmt"
	"os/exec"

	"github.com/sem-hub/snake-net/internal/configs"
)

func OpenFirewallPort(port uint16, protocol string) error {
	logger := configs.InitLogger("firewall")
	logger.Info("Opening firewall port", "port", port)
	cmd := exec.Command("iptables", "-I", "INPUT", "-p", protocol, "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT")
	if err := cmd.Run(); err != nil {
		logger.Error("Error:" + err.Error())
		logger.Debug("Command:", "cmd", cmd.String())
		return err
	}
	cmd = exec.Command("ip6tables", "-I", "INPUT", "-p", protocol, "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT")
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
	cmd := exec.Command("iptables", "-D", "INPUT", "-p", protocol, "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT")
	if err := cmd.Run(); err != nil {
		logger.Error("Error:" + err.Error())
		logger.Debug("Command:", "cmd", cmd.String())
		return err
	}
	cmd = exec.Command("ip6tables", "-D", "INPUT", "-p", protocol, "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT")
	if err := cmd.Run(); err != nil {
		logger.Error("Error:" + err.Error())
		logger.Debug("Command:", "cmd", cmd.String())
		return err
	}
	return nil
}
