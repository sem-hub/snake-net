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
	Main Main `toml:"main"`
	Tls  Tls  `toml:"tls"`
	Tun  Tun  `toml:"tun"`
	Log  Log  `toml:"log"`
}

type Main struct {
	Mode       string `toml:"mode"`
	Debug      bool   `toml:"debug"`
	Secret     string
	Protocol   string `toml:"protocol"`
	RemoteAddr string `toml:"remote_addr"`
	RemotePort uint16 `toml:"remote_port"`
	LocalAddr  string `toml:"local_addr"`
	LocalPort  uint16 `toml:"local_port"`
	ClientId   string `toml:"id"`
	RetryDelay int    `toml:"retry_delay"`
	Attempts   int    `toml:"attempts"`
}

type Tls struct {
	CertFile string `toml:"cert_file"`
	KeyFile  string `toml:"key_file"`
	CAFile   string `toml:"ca_file"`
}

type Tun struct {
	Name       string   `toml:"name"`
	MTU        int      `toml:"mtu"`
	TunAddrStr []string `toml:"tun_addr"`
}

type Log struct {
	Main      string `toml:"main"`
	Protocol  string `toml:"protocol"`
	Network   string `toml:"network"`
	Crypt     string `toml:"crypt"`
	Clients   string `toml:"clients"`
	Tun       string `toml:"tun"`
	Route     string `toml:"route"`
	Transport string `toml:"transport"`
}

type RuntimeConfig struct {
	Mode       string
	Debug      bool
	Protocol   string
	RemoteAddr string
	RemotePort uint16
	LocalAddr  string
	LocalPort  uint16
	TunAddrs   []utils.Cidr
	TunMTU     int
	TunName    string
	ClientId   string
	Secret     string
}

var (
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
			TunMTU:     configFile.Tun.MTU,
			TunName:    configFile.Tun.Name,
			ClientId:   configFile.Main.ClientId,
			Secret:     configFile.Main.Secret,
		}
		if len(configFile.Tun.TunAddrStr) > 0 {
			for _, addr := range configFile.Tun.TunAddrStr {
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

func getLevelByString(levelStr string) slog.Level {
	switch strings.ToLower(levelStr) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelError
	}
}

func getLenvelByModule(module string) slog.Level {
	switch module {
	case "main":
		return getLevelByString(configFile.Log.Main)
	case "network":
		return getLevelByString(configFile.Log.Network)
	case "tun":
		return getLevelByString(configFile.Log.Tun)
	case "route":
		return getLevelByString(configFile.Log.Route)
	case "protocol":
		return getLevelByString(configFile.Log.Protocol)
	case "clients":
		return getLevelByString(configFile.Log.Clients)
	case "crypt":
		return getLevelByString(configFile.Log.Crypt)
	case "transport":
		return getLevelByString(configFile.Log.Transport)
	default:
		// XXX log.Debug here
		if configFile.Main.Debug {
			return slog.LevelDebug
		} else {
			return slog.LevelInfo
		}
	}
}

func adjustAttrs(groups []string, a slog.Attr) slog.Attr {
	if a.Key == slog.TimeKey && len(groups) == 0 {
		a.Value = slog.StringValue(a.Value.Time().Format("15:04:05.000"))
	}
	return a
}

func InitLogger(module string) *slog.Logger {
	level := getLenvelByModule(module)
	logger := slog.New(
		slog.NewTextHandler(
			os.Stderr,
			&slog.HandlerOptions{
				ReplaceAttr: adjustAttrs,
				Level:       level,
			},
		),
	).With("module", module)
	return logger
}
