package configs

import (
	"log/slog"
	"os"
)

type Config struct {
	Mode       string `toml:"mode"`
	Protocol   string `toml:"protocol"`
	RemoteAddr string `toml:"remote_addr"`
	RemotePort string `toml:"remote_port"`
	LocalAddr  string `toml:"local_addr"`
	LocalPort  string `toml:"local_port"`
	TunAddr    string `toml:"tun_addr"`
}

var (
	logger *slog.Logger
)

func NewConfig() *Config {
	return &Config{}
}

func removeTime(groups []string, a slog.Attr) slog.Attr {
	if a.Key == slog.TimeKey && len(groups) == 0 {
		return slog.Attr{}
	}
	return a
}

func InitLogger(level slog.Level) {
	logger = slog.New(
		slog.NewTextHandler(
			os.Stderr,
			&slog.HandlerOptions{
				ReplaceAttr: removeTime,
				Level:       slog.LevelDebug,
			},
		),
	)
	slog.SetDefault(logger)
}

func GetLogger() *slog.Logger {
	return logger
}
