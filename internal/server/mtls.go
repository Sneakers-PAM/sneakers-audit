// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"errors"
	"fmt"

	log "github.com/Bugs5382/go-log"
	mtls "github.com/Bugs5382/go-mtls"
)

// MTLSFromEnv builds the mutual-TLS provider from MTLS_CERT_FILE,
// MTLS_KEY_FILE and MTLS_CA_FILE. With none of the three set it returns nil:
// the service stays on plaintext gRPC (local runs and tests). With only some
// set, or with files that cannot be read, it fails, so a half-configured
// deployment stops at boot instead of serving plaintext by accident.
//
// The provider re-reads the files when they change, so a renewed certificate
// needs no restart; a renewal that cannot be read keeps the last good files
// and is logged as a warning.
func MTLSFromEnv(getenv func(string) string, lg log.Logger) (*mtls.Provider, error) {
	names := []string{mtls.EnvCertFile, mtls.EnvKeyFile, mtls.EnvCAFile}
	set := 0
	for _, n := range names {
		if getenv(n) != "" {
			set++
		}
	}
	if set == 0 {
		lg.Info("mtls off: plaintext gRPC", log.F("reason", "no MTLS_* file variable is set"))
		return nil, nil
	}
	certPath, caPath := getenv(mtls.EnvCertFile), getenv(mtls.EnvCAFile)
	files := mtls.Files{Cert: certPath, Key: getenv(mtls.EnvKeyFile), CA: caPath}
	if set < len(names) {
		var missing []string
		for _, n := range names {
			if getenv(n) == "" {
				missing = append(missing, n)
			}
		}
		return nil, fmt.Errorf("%w: set %v", mtls.ErrNotConfigured, missing)
	}
	p, err := mtls.NewProvider(files, mtls.WithErrorHandler(func(err error) {
		lg.Warn("mtls certificate reload failed; keeping the last good files", log.F("error", err.Error()))
	}))
	if err != nil {
		var fe *mtls.FileError
		if errors.As(err, &fe) {
			lg.Error(err, "mtls file unusable", log.F("role", fe.Role), log.F("path", fe.Path))
		}
		return nil, fmt.Errorf("mtls: %w", err)
	}
	lg.Info("mtls on: client certificates required", log.F("cert_path", certPath), log.F("ca_path", caPath))
	return p, nil
}
