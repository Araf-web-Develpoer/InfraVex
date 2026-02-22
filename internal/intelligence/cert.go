package intelligence

import (
	"crypto/tls"
	"fmt"
	"time"

	"veex0x01-intel/pkg/logger"
)

// CertInfo contains useful certificate data
type CertInfo struct {
	Issuer    string
	Subject   string
	DNSNames  []string
	NotBefore time.Time
	NotAfter  time.Time
	Expired   bool
}

// FetchCert extracts X.509 cert info by initiating a TLS handshake
func FetchCert(ip string, port int, timeout time.Duration) (*CertInfo, error) {
	target := fmt.Sprintf("%s:%d", ip, port)

	conf := &tls.Config{
		InsecureSkipVerify: true, // We must accept any cert to gather info during scanning
	}

	dialer := &net.Dialer{Timeout: timeout}
	
	// Fast TLS connection attempt
	conn, err := tls.DialWithDialer(dialer, "tcp", target, conf)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Get array of certificates provided by server
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates returned by server")
	}

	// Primarily care about the leaf cert (index 0)
	cert := certs[0]

	info := &CertInfo{
		Issuer:    cert.Issuer.String(),
		Subject:   cert.Subject.String(),
		DNSNames:  cert.DNSNames,
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		Expired:   time.Now().After(cert.NotAfter),
	}

	if info.Expired {
		logger.Warn("Discovered EXPIRED certificate", map[string]interface{}{
			"ip": target,
			"subject": info.Subject,
			"expired_at": info.NotAfter.String(),
		})
	}

	return info, nil
}
