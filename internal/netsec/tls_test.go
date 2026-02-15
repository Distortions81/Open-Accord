package netsec

import (
	"bytes"
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnsureSelfSignedCertCreatesAndReusesFiles(t *testing.T) {
	tmp := t.TempDir()
	certPath := filepath.Join(tmp, "server.crt")
	keyPath := filepath.Join(tmp, "server.key")

	if err := EnsureSelfSignedCert(certPath, keyPath, []string{"127.0.0.1", "localhost"}); err != nil {
		t.Fatalf("first ensure failed: %v", err)
	}
	certBefore, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert before failed: %v", err)
	}
	keyBefore, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key before failed: %v", err)
	}

	if err := EnsureSelfSignedCert(certPath, keyPath, []string{"127.0.0.1", "localhost"}); err != nil {
		t.Fatalf("second ensure failed: %v", err)
	}
	certAfter, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert after failed: %v", err)
	}
	keyAfter, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key after failed: %v", err)
	}

	if len(certBefore) == 0 || len(keyBefore) == 0 {
		t.Fatalf("expected non-empty cert and key")
	}
	if !bytes.Equal(certBefore, certAfter) || !bytes.Equal(keyBefore, keyAfter) {
		t.Fatalf("expected existing cert/key to be reused without rotation")
	}
}

func TestServerTLSConfigLoadsPairAndEnforcesMinVersion(t *testing.T) {
	tmp := t.TempDir()
	certPath := filepath.Join(tmp, "server.crt")
	keyPath := filepath.Join(tmp, "server.key")
	if err := EnsureSelfSignedCert(certPath, keyPath, []string{"localhost"}); err != nil {
		t.Fatalf("ensure cert failed: %v", err)
	}

	cfg, err := ServerTLSConfig(certPath, keyPath)
	if err != nil {
		t.Fatalf("server tls config failed: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("unexpected min tls version: got=%d want=%d", cfg.MinVersion, tls.VersionTLS12)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("expected one certificate, got %d", len(cfg.Certificates))
	}
}

func TestClientTLSConfigInsecureDefaults(t *testing.T) {
	cfg := ClientTLSConfigInsecure()
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("unexpected min tls version: got=%d want=%d", cfg.MinVersion, tls.VersionTLS12)
	}
	if !cfg.InsecureSkipVerify {
		t.Fatalf("expected insecure skip verify for local/dev testing")
	}
}

func TestShouldRotateWhenFilesAreMissing(t *testing.T) {
	tmp := t.TempDir()
	certPath := filepath.Join(tmp, "missing.crt")
	keyPath := filepath.Join(tmp, "missing.key")

	rotate, err := shouldRotateSelfSignedCert(certPath, keyPath, 24*time.Hour)
	if err != nil {
		t.Fatalf("shouldRotate failed: %v", err)
	}
	if !rotate {
		t.Fatalf("expected rotation when cert/key files are missing")
	}
}
