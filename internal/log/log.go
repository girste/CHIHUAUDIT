// Package log provides structured logging for the application.
package log

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var logger *zap.Logger

func init() {
	// Console encoder for human-readable output
	config := zap.Config{
		Level:    zap.NewAtomicLevelAt(getLogLevel()),
		Encoding: "console",
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:        "time",
			LevelKey:       "level",
			MessageKey:     "msg",
			StacktraceKey:  "stacktrace",
			LineEnding:     zapcore.DefaultLineEnding,
			EncodeLevel:    zapcore.CapitalColorLevelEncoder,
			EncodeTime:     zapcore.ISO8601TimeEncoder,
			EncodeDuration: zapcore.StringDurationEncoder,
			EncodeCaller:   zapcore.ShortCallerEncoder,
		},
		OutputPaths:      []string{"stderr"},
		ErrorOutputPaths: []string{"stderr"},
	}

	var err error
	logger, err = config.Build()
	if err != nil {
		// Fallback to production logger
		logger, _ = zap.NewProduction()
	}
}

func getLogLevel() zapcore.Level {
	if lvl := os.Getenv("LOG_LEVEL"); lvl != "" {
		switch lvl {
		case "debug", "DEBUG":
			return zapcore.DebugLevel
		case "info", "INFO":
			return zapcore.InfoLevel
		case "warn", "WARN", "warning", "WARNING":
			return zapcore.WarnLevel
		case "error", "ERROR":
			return zapcore.ErrorLevel
		case "fatal", "FATAL":
			return zapcore.FatalLevel
		}
	}
	return zapcore.InfoLevel
}

// Debug logs a debug message
func Debug(msg string) {
	logger.Debug(msg)
}

// Debugf logs a formatted debug message
func Debugf(format string, args ...interface{}) {
	logger.Sugar().Debugf(format, args...)
}

// Info logs an info message
func Info(msg string) {
	logger.Info(msg)
}

// Infof logs a formatted info message
func Infof(format string, args ...interface{}) {
	logger.Sugar().Infof(format, args...)
}

// Warn logs a warning message
func Warn(msg string) {
	logger.Warn(msg)
}

// Warnf logs a formatted warning message
func Warnf(format string, args ...interface{}) {
	logger.Sugar().Warnf(format, args...)
}

// Error logs an error message
func Error(msg string) {
	logger.Error(msg)
}

// Errorf logs a formatted error message
func Errorf(format string, args ...interface{}) {
	logger.Sugar().Errorf(format, args...)
}

// ErrorWithErr logs an error with the error object
func ErrorWithErr(err error, msg string) {
	logger.Error(msg, zap.Error(err))
}

// Fatal logs a fatal message and exits
func Fatal(msg string) {
	logger.Fatal(msg)
}

// Fatalf logs a formatted fatal message and exits
func Fatalf(format string, args ...interface{}) {
	logger.Sugar().Fatalf(format, args...)
}

// FatalWithErr logs a fatal error with the error object and exits
func FatalWithErr(err error, msg string) {
	logger.Fatal(msg, zap.Error(err))
}

// GetLogger returns the underlying zap logger for advanced usage
func GetLogger() *zap.Logger {
	return logger
}
