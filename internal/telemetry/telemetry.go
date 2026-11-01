// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package telemetry holds what this service adds to go-otel: the two export
// switches, the filters on exported logs, the export error handler and the
// optional otlp health dependency.
package telemetry

import (
	"context"
	"errors"
	"io"
	"regexp"
	"slices"
	"strings"

	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	otel "github.com/Bugs5382/go-otel"
	otelapi "go.opentelemetry.io/otel"
	"google.golang.org/grpc/status"
)

const (
	// EnvInsecureSkipVerify turns off the collector's certificate check when
	// it is exactly "true". Logs stay off while it is on.
	EnvInsecureSkipVerify = "OTLP_INSECURE_SKIP_VERIFY"
	// EnvLogsEnabled turns log export on when it is exactly "true".
	EnvLogsEnabled = "OTLP_LOGS_ENABLED"
)

// allowedLogFields is every log field that may leave the service. Each holds
// an id, count, duration, class, state or short enum. Anything else stays
// off: the error, panic and stack text, the issuer, audience and JWKS URLs,
// caller names and refusal reasons. A new log field exports nothing until it
// is added here. Audit entries are never logged at all.
var allowedLogFields = []string{
	"attempt",
	"attempts",
	"bearer_file",
	"ca_file",
	"code",
	"dependencies",
	"dependency",
	"duration_ms",
	"error_class",
	"from",
	"jwks_override",
	"kept_keys",
	"keys",
	"method",
	"port",
	"required",
	"retry_in",
	"to",
}

var tokenPattern = regexp.MustCompile(`\bsnk_[A-Za-z0-9_\-]+`)

// AllowedLogFields returns a copy of the exported log field names.
func AllowedLogFields() []string { return slices.Clone(allowedLogFields) }

func enabled(getenv func(string) string, name string) bool { return getenv(name) == "true" }

// Options returns the go-otel options the environment asks for. With both
// variables unset it behaves as a plain otel.Init.
func Options(getenv func(string) string) []otel.Option {
	return []otel.Option{
		otel.WithInsecureSkipVerify(enabled(getenv, EnvInsecureSkipVerify)),
		otel.WithLogs(enabled(getenv, EnvLogsEnabled)),
		otel.WithLogAllowFields(allowedLogFields...),
		otel.WithLogRedactPatterns(tokenPattern),
	}
}

// LogOutput returns what the service logger writes to: stdout alone, or
// stdout and go-otel's log writer when log export is on. The logger is built
// before Init; the writer discards until then.
func LogOutput(getenv func(string) string, stdout io.Writer) io.Writer {
	if !enabled(getenv, EnvLogsEnabled) {
		return stdout
	}
	return io.MultiWriter(stdout, otel.LogWriter())
}

// SetErrorHandler sends OpenTelemetry's background errors to lg in place of
// its default raw print to stderr. Only the class is logged, because the text
// can name the endpoint and echo headers.
func SetErrorHandler(lg log.Logger) {
	otelapi.SetErrorHandler(otelapi.ErrorHandlerFunc(func(err error) {
		lg.Warn("otel export failed", log.F("error_class", errorClass(err)))
	}))
}

func errorClass(err error) string {
	var gs interface{ GRPCStatus() *status.Status }
	if errors.As(err, &gs) {
		return gs.GRPCStatus().Code().String()
	}
	return health.ClassError
}

var errExportFailing = errors.New("otlp export failing")

// Dependencies returns the optional otlp dependency, or nothing when no
// endpoint is set. It never affects readiness, and reports a class rather
// than go-otel's error text.
func Dependencies(endpoint string, getenv func(string) string) []health.Dependency {
	if strings.TrimSpace(endpoint) == "" {
		return nil
	}
	logs := enabled(getenv, EnvLogsEnabled)
	return []health.Dependency{{Name: "otlp", Check: func(context.Context) error {
		s := otel.ExportState()
		if failing(s.Traces) || failing(s.Metrics) || (logs && failing(s.Logs)) {
			return errExportFailing
		}
		return nil
	}}}
}

func failing(s otel.SignalStatus) bool { return s.LastErrorAt.After(s.LastSuccess) }
