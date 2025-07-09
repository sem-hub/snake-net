package configs

type Config struct {
	Mode        string `toml:"mode"`
	Protocol    string `toml:"protocol"`
	RemoteAddr  string `toml:"remote_addr"`
	RemotePort  string `toml:"remote_port"`
	LocalAddr   string `toml:"local_addr"`
	LocalPort   string `toml:"local_port"`
	TlsCertFile string `toml:"tls_cert"`
	TlsKeyFile  string `toml:"tls_key"`
}

func NewConfig() *Config {
	return &Config{}
}
