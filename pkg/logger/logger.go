package logger

import (
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// InitConfig initializes the zerolog logger for CLI usage
func InitConfig(debug bool) {
	zerolog.TimeFieldFormat = time.RFC3339

	// Console writer for clean CLI experience
	consoleWriter := zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: "15:04:05",
	}

	// Setup log level
	logLevel := zerolog.InfoLevel
	if debug {
		logLevel = zerolog.DebugLevel
	}
	zerolog.SetGlobalLevel(logLevel)

	// Set the global logger
	log.Logger = zerolog.New(consoleWriter).With().Timestamp().Logger()
}

// Info logs an informational message
func Info(msg string, fields map[string]interface{}) {
	logMessage(log.Info(), msg, fields)
}

// Warn logs a warning message
func Warn(msg string, fields map[string]interface{}) {
	logMessage(log.Warn(), msg, fields)
}

// Error logs an error message
func Error(msg string, err error) {
	log.Error().Err(err).Msg(msg)
}

// Fatal logs a critical error and exits
func Fatal(msg string, err error) {
	log.Fatal().Err(err).Msg(msg)
}

// helper to format arbitrary fields
func logMessage(event *zerolog.Event, msg string, fields map[string]interface{}) {
	for k, v := range fields {
		event = event.Interface(k, v)
	}
	event.Msg(msg)
}
