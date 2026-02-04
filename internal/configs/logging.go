package configs

import (
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"strings"

	"github.com/fatih/color"
)

type ColorHandlerOptions struct {
	slog.HandlerOptions
	Module string
}

type ColorHandler struct {
	slog.Handler
	logOutput *log.Logger
	module    string
}

func NewColorHandler(out io.Writer, opts ColorHandlerOptions) *ColorHandler {
	h := &ColorHandler{
		Handler:   slog.NewTextHandler(out, &opts.HandlerOptions),
		logOutput: log.New(out, "", 0),
	}
	h.module = opts.Module

	return h
}

func (h *ColorHandler) Handle(ctx context.Context, r slog.Record) error {
	level := r.Level.String() + ":"

	switch r.Level {
	case slog.LevelDebug:
		level = color.MagentaString(level)
	case slog.LevelInfo:
		level = color.BlueString(level)
	case slog.LevelWarn:
		level = color.YellowString(level)
	case slog.LevelError:
		level = color.RedString(level)
	}

	fields := make(map[string]interface{}, r.NumAttrs())
	r.Attrs(func(a slog.Attr) bool {
		fields[a.Key] = a.Value.Any()

		return true
	})

	b := ""
	for k, v := range fields {
		b += fmt.Sprintf("%s=%v ", k, v)
	}

	timeStr := r.Time.Format("[15:05:05.000]")
	msg := color.CyanString(r.Message)

	h.logOutput.Println(timeStr, color.YellowString(h.module), level, msg, color.WhiteString(string(b)))

	return nil
}

func (h *ColorHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ColorHandler{
		Handler:   h.Handler.WithAttrs(attrs),
		logOutput: h.logOutput,
	}
}

func (h *ColorHandler) WithGroup(name string) slog.Handler {
	return &ColorHandler{
		Handler:   h.Handler.WithGroup(name),
		logOutput: h.logOutput,
	}
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

func InitLogger(module string) *slog.Logger {
	level := getLenvelByModule(module)
	log.Println("Initializing logger for module", module, "with level", level.String())
	logger := slog.New(
		NewColorHandler(
			os.Stderr,
			ColorHandlerOptions{
				HandlerOptions: slog.HandlerOptions{
					Level: level,
				},
				Module: module,
			},
		),
	)
	return logger
}
