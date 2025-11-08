package configs

import (
	"log/slog"
	"net"
	"net/netip"
	"os"

	"github.com/sem-hub/snake-net/internal/utils"
)

type ConfigFile struct {
	Main Main `toml:"main"`
	Log  Log  `toml:"log"`
}

type Main struct {
	Mode       string   `toml:"mode"`
	Debug      bool     `toml:"debug"`
	Protocol   string   `toml:"protocol"`
	RemoteAddr string   `toml:"remote_addr"`
	RemotePort uint32   `toml:"remote_port"`
	LocalAddr  string   `toml:"local_addr"`
	LocalPort  uint32   `toml:"local_port"`
	TunAddrStr []string `toml:"tun_addr"`
}

type Log struct {
	Protocol string `toml:"protocol"`
	Network  string `toml:"network"`
	Crypt    string `toml:"crypt"`
	Clients  string `toml:"clients"`
}

type RuntimeConfig struct {
	Mode       string
	Debug      bool
	Protocol   string
	RemoteAddr string
	RemotePort uint32
	LocalAddr  string
	LocalPort  uint32
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
			Mode:       configFile.Main.Mode,
			Debug:      configFile.Main.Debug,
			Protocol:   configFile.Main.Protocol,
			RemoteAddr: configFile.Main.RemoteAddr,
			RemotePort: configFile.Main.RemotePort,
			LocalAddr:  configFile.Main.LocalAddr,
			LocalPort:  configFile.Main.LocalPort,
			TunAddrs:   []utils.Cidr{},
			LogLevel:   slog.LevelInfo,
		}
		if len(configFile.Main.TunAddrStr) > 0 {
			for _, addr := range configFile.Main.TunAddrStr {
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
