package util

import (
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var defaultLogger *zap.Logger

func init() {
	defaultLogger = NewLogger("mcp-watchdog")
}

// NewLogger creates a new logger with the specified name
func NewLogger(name string) *zap.Logger {
	level := getLogLevel()

	config := zap.Config{
		Level:    zap.NewAtomicLevelAt(level),
		Encoding: "console",
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:        "time",
			LevelKey:       "level",
			NameKey:        "logger",
			MessageKey:     "msg",
			StacktraceKey:  "stacktrace",
			LineEnding:     zapcore.DefaultLineEnding,
			EncodeLevel:    zapcore.CapitalColorLevelEncoder,
			EncodeTime:     zapcore.ISO8601TimeEncoder,
			EncodeDuration: zapcore.StringDurationEncoder,
		},
		OutputPaths:      []string{"stderr"},
		ErrorOutputPaths: []string{"stderr"},
	}

	logger, _ := config.Build()
	return logger.Named(name)
}

func getLogLevel() zapcore.Level {
	levelStr := strings.ToUpper(os.Getenv("MCP_SECURITY_LOG_LEVEL"))
	switch levelStr {
	case "DEBUG":
		return zapcore.DebugLevel
	case "INFO":
		return zapcore.InfoLevel
	case "WARN", "WARNING":
		return zapcore.WarnLevel
	case "ERROR":
		return zapcore.ErrorLevel
	case "CRITICAL", "FATAL":
		return zapcore.FatalLevel
	default:
		return zapcore.WarnLevel
	}
}

// GetLogger returns the default logger
func GetLogger() *zap.Logger {
	return defaultLogger
}
