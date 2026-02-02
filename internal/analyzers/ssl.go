package analyzers

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/girste/chihuaudit/internal/config"
	"github.com/girste/chihuaudit/internal/system"
)

type SSLAnalyzer struct{}

func (a *SSLAnalyzer) Name() string           { return "ssl" }
func (a *SSLAnalyzer) RequiresSudo() bool     { return true }
func (a *SSLAnalyzer) Timeout() time.Duration { return system.TimeoutLong }

type certInfo struct {
	Path       string `json:"path"`
	Subject    string `json:"subject"`
	Issuer     string `json:"issuer"`
	NotBefore  string `json:"notBefore"`
	NotAfter   string `json:"notAfter"`
	DaysLeft   int    `json:"daysLeft"`
	IsExpired  bool   `json:"isExpired"`
	IsExpiring bool   `json:"isExpiring"`
}

func (a *SSLAnalyzer) Analyze(ctx context.Context, cfg *config.Config) (*Result, error) {
	result := NewResult()

	if !system.CommandExists("openssl") {
		result.Data = map[string]interface{}{"available": false}
		return result, nil
	}

	certDirs := []string{
		system.HostPath("/etc/ssl/certs"),
		system.HostPath("/etc/pki/tls/certs"),
		system.HostPath("/etc/letsencrypt/live"),
		system.HostPath("/etc/caddy/certificates"),
	}

	var certificates []certInfo
	expiredCount := 0
	expiringCount := 0

	for _, dir := range certDirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue
		}
		certs := a.scanDirectory(ctx, dir)
		for _, cert := range certs {
			if cert.IsExpired {
				expiredCount++
			} else if cert.IsExpiring {
				expiringCount++
			}
			certificates = append(certificates, cert)
		}
	}

	result.Data = map[string]interface{}{
		"available":         true,
		"totalCertificates": len(certificates),
		"expiredCount":      expiredCount,
		"expiringCount":     expiringCount,
		"certificates":      certificates,
	}

	if expiredCount > 0 {
		result.AddIssue(NewIssue(SeverityCritical, "Expired SSL certificates found", "Renew expired certificates immediately"))
	}
	if expiringCount > 0 {
		result.AddIssue(NewIssue(SeverityHigh, "SSL certificates expiring within 30 days", "Plan certificate renewal"))
	}

	return result, nil
}

func (a *SSLAnalyzer) scanDirectory(ctx context.Context, dir string) []certInfo {
	var certs []certInfo

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".crt") && !strings.HasSuffix(path, ".pem") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			cmdResult, _ := system.RunCommandSudo(ctx, system.TimeoutShort, "cat", path)
			if cmdResult == nil || !cmdResult.Success {
				return nil
			}
			data = []byte(cmdResult.Stdout)
		}

		block, _ := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil
		}

		now := time.Now()
		daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)

		certs = append(certs, certInfo{
			Path:       path,
			Subject:    cert.Subject.CommonName,
			Issuer:     cert.Issuer.CommonName,
			NotBefore:  cert.NotBefore.Format("2006-01-02"),
			NotAfter:   cert.NotAfter.Format("2006-01-02"),
			DaysLeft:   daysLeft,
			IsExpired:  now.After(cert.NotAfter),
			IsExpiring: daysLeft > 0 && daysLeft <= 30,
		})

		return nil
	})

	return certs
}
