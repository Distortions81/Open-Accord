package netsec

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const defaultSelfSignedMaxAge = 30 * 24 * time.Hour

// EnsureSelfSignedCert creates a self-signed TLS cert/key if either file is missing.
func EnsureSelfSignedCert(certPath string, keyPath string, hosts []string) error {
	certPath = strings.TrimSpace(certPath)
	keyPath = strings.TrimSpace(keyPath)
	if certPath == "" || keyPath == "" {
		return fmt.Errorf("certificate and key paths are required")
	}
	rotate, err := shouldRotateSelfSignedCert(certPath, keyPath, defaultSelfSignedMaxAge)
	if err != nil {
		return err
	}
	if !rotate {
		return nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return err
	}

	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "goaccord-self-signed",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
			continue
		}
		tpl.DNSNames = append(tpl.DNSNames, h)
	}
	if len(tpl.DNSNames) == 0 && len(tpl.IPAddresses) == 0 {
		tpl.DNSNames = append(tpl.DNSNames, "localhost")
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return err
	}
	return nil
}

func shouldRotateSelfSignedCert(certPath string, keyPath string, maxAge time.Duration) (bool, error) {
	if _, err := os.Stat(certPath); err != nil {
		if os.IsNotExist(err) {
			return true, nil
		}
		return false, err
	}
	if _, err := os.Stat(keyPath); err != nil {
		if os.IsNotExist(err) {
			return true, nil
		}
		return false, err
	}
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		return false, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return true, nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true, nil
	}
	now := time.Now()
	if cert.NotAfter.Before(now) {
		return true, nil
	}
	if maxAge > 0 && now.Sub(cert.NotBefore) > maxAge {
		return true, nil
	}
	return false, nil
}

func ServerTLSConfig(certPath string, keyPath string) (*tls.Config, error) {
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{pair},
	}, nil
}

func ClientTLSConfigInsecure() *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	}
}
