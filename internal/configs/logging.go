package configs

import (
	"log/slog"
	"os"
	"strings"
)

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
	case "socks5":
		return getLevelByString(configFile.Log.Socks5)
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
