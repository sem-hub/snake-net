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

const (
	LevelTrace = slog.Level(-8)
	LevelFatal = slog.Level(12)
)

var loggers map[string]*ColorLogger

type ColorLogger struct {
	slog.Logger
}

type ColorHandlerOptions struct {
	slog.HandlerOptions
	Module  string
	NoColor bool
}

type ColorHandler struct {
	slog.Handler
	logOutput *log.Logger
	module    string
	noColor   bool
}

func NewColorHandler(out io.Writer, opts ColorHandlerOptions) *ColorHandler {
	h := &ColorHandler{
		Handler:   slog.NewTextHandler(out, &opts.HandlerOptions),
		logOutput: log.New(out, "", 0),
	}
	h.module = opts.Module
	h.noColor = opts.NoColor

	return h
}
func (l *ColorLogger) Trace(msg string, args ...any) {
	ctx := context.Background()
	l.Log(ctx, LevelTrace, msg, args...)
}

func (l *ColorLogger) Fatal(msg string, args ...any) {
	ctx := context.Background()
	l.Log(ctx, LevelFatal, msg, args...)
	// Duplicate the log message to stdout if writing to a file
	if configFile.Log.File != "" {
		fmt.Fprintln(os.Stdout, "FATAL:", msg, args)
	}
	os.Exit(1)
}

func (h *ColorHandler) Handle(ctx context.Context, r slog.Record) error {
	level := r.Level.String() + ":"

	if !h.noColor {
		switch r.Level {
		case LevelTrace:
			level = color.GreenString("TRACE:")
		case slog.LevelDebug:
			level = color.MagentaString(level)
		case slog.LevelInfo:
			level = color.BlueString(level)
		case slog.LevelWarn:
			level = color.YellowString(level)
		case slog.LevelError:
			level = color.RedString(level)
		case LevelFatal:
			level = color.RedString("FATAL:")
		}
	} else {
		switch r.Level {
		case LevelTrace:
			level = "TRACE:"
		case LevelFatal:
			level = "FATAL:"
		}
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
	if h.noColor {
		h.logOutput.Println(timeStr, level, h.module, r.Message, b)
		return nil
	} else {
		msg := color.CyanString(r.Message)
		h.logOutput.Println(timeStr, color.YellowString(h.module), level, msg, color.WhiteString(string(b)))
	}

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
	case "trace":
		return LevelTrace
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	case "fatal":
		return LevelFatal
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
	case "icmp":
		return getLevelByString(configFile.Log.ICMP)
	case "firewall":
		return getLevelByString(configFile.Log.Firewall)
	default:
		// XXX log.Debug here
		if configFile.Main.Debug {
			return slog.LevelDebug
		} else {
			return slog.LevelInfo
		}
	}
}

func InitLogger(module string) *ColorLogger {
	if loggers == nil {
		loggers = make(map[string]*ColorLogger)
	}
	if logger, exists := loggers[module]; exists {
		return logger
	}
	level := getLenvelByModule(module)
	mainLogger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: getLenvelByModule("main")}))
	mainLogger.Debug("Initializing logger for module", "module", module, "with level", level.String())
	var out io.Writer
	noColor := false
	if configFile.Log.NoColor {
		noColor = true
	}
	if configFile.Log.File != "" {
		f, err := os.OpenFile(configFile.Log.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("Failed to open log file: %v", err)
		}
		out = f
		noColor = true
	} else {
		out = os.Stderr
	}
	logger := slog.New(
		NewColorHandler(
			out,
			ColorHandlerOptions{
				HandlerOptions: slog.HandlerOptions{
					Level: level,
				},
				Module:  module,
				NoColor: noColor,
			},
		),
	)
	newLogger := &ColorLogger{*logger}
	loggers[module] = newLogger
	return newLogger
}
