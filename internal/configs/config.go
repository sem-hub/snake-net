package configs

import (
	"net"
	"net/netip"

	"github.com/sem-hub/snake-net/internal/utils"
)

type ConfigFile struct {
	Main  Main  `toml:"main"`
	Tls   Tls   `toml:"tls"`
	Tun   Tun   `toml:"tun"`
	Log   Log   `toml:"log"`
	Crypt Crypt `toml:"crypt"`
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

type Crypt struct {
	Engine string `toml:"engine"`
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
	CertFile   string
	KeyFile    string
	CAFile     string
	Engine     string
	Attempts   int
	RetryDelay int
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
			CertFile:   configFile.Tls.CertFile,
			KeyFile:    configFile.Tls.KeyFile,
			CAFile:     configFile.Tls.CAFile,
			Engine:     configFile.Crypt.Engine,
			Attempts:   configFile.Main.Attempts,
			RetryDelay: configFile.Main.RetryDelay,
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
