package configs

import (
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/sem-hub/snake-net/internal/utils"
)

type ConfigFile struct {
	Mode       string `toml:"mode"`
	Debug      bool   `toml:"debug"`
	Protocol   string `toml:"protocol"`
	RemoteAddr string `toml:"remote_addr"`
	RemotePort string `toml:"remote_port"`
	LocalAddr  string `toml:"local_addr"`
	LocalPort  string `toml:"local_port"`
	TunAddrStr string `toml:"tun_addr"`
}

type RuntimeConfig struct {
	Mode       string
	Debug      bool
	Protocol   string
	RemoteAddr string
	RemotePort string
	LocalAddr  string
	LocalPort  string
	TunAddrs   []utils.Cidr
	LogLevel   slog.Level
}

var (
	logger     *slog.Logger
	config     *RuntimeConfig = nil
	configFile *ConfigFile    = nil
)

func GetConfigFile() *ConfigFile {
	if configFile == nil {
		configFile = &ConfigFile{}
	}
	return configFile
}

func GetConfig() *RuntimeConfig {
	if config == nil {
		config = &RuntimeConfig{
			Mode:       configFile.Mode,
			Debug:      configFile.Debug,
			Protocol:   configFile.Protocol,
			RemoteAddr: configFile.RemoteAddr,
			RemotePort: configFile.RemotePort,
			LocalAddr:  configFile.LocalAddr,
			LocalPort:  configFile.LocalPort,
			TunAddrs:   []utils.Cidr{},
			LogLevel:   slog.LevelInfo,
		}
		if configFile.TunAddrStr != "" {
			for _, addr := range strings.Split(configFile.TunAddrStr, ",") {
				logger.Debug("Adding TUN address from config file", "addr", addr)
				ip, network, _ := net.ParseCIDR(addr)
				netIP, _ := netip.AddrFromSlice(ip)
				config.TunAddrs = append(config.TunAddrs,
					utils.Cidr{
						IP:      netIP.Unmap(),
						Network: network,
					})
			}
		}
	}
	return config
}

/*
func removeTime(groups []string, a slog.Attr) slog.Attr {
	if a.Key == slog.TimeKey && len(groups) == 0 {
		return slog.Attr{}
	}
	return a
}*/

func InitLogger(level slog.Level) {
	logger = slog.New(
		slog.NewTextHandler(
			os.Stderr,
			&slog.HandlerOptions{
				//ReplaceAttr: removeTime,
				Level: level,
			},
		),
	)
	slog.SetDefault(logger)
}

func GetLogger() *slog.Logger {
	return logger
}
