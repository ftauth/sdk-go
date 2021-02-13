package ftauth

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
	"sync"
)

var (
	errInvalidCertificate = errors.New("invalid certificate")
)

// The main certificate repository.
var (
	certRepo             = &CertificateRepository{}
	defaultConfiguration = &SecurityConfiguration{
		TrustPublicPKI: true,
	}
	defaultConfigurationKey = "default"
)

// CertificateRepository holds a map of hosts to certificate pools
// for use with TLS handshake verification (i.e. certificate pinning).
type CertificateRepository struct {
	m sync.Map
}

// GetCertificateRepository returns the main certificate repo for adding/removing
// security configurations.
func GetCertificateRepository() *CertificateRepository {
	return certRepo
}

// GetDefaultConfiguration returns the default security configuration, i.e. the configuration
// used when a server's configuration has not been explicitly set.
func (cr *CertificateRepository) GetDefaultConfiguration() *SecurityConfiguration {
	sc := cr.GetSecurityConfiguration(defaultConfigurationKey)
	if sc == nil {
		return defaultConfiguration
	}
	return sc
}

// SetDefaultConfiguration sets the default security configuration, i.e. the configuration
// used when a server's configuration has not been explicitly set.
func (cr *CertificateRepository) SetDefaultConfiguration(sc *SecurityConfiguration) {
	cr.m.Store(defaultConfigurationKey, sc)
}

// AddSecurityConfiguration configures the TLS client for request to the specified host.
func (cr *CertificateRepository) AddSecurityConfiguration(sc *SecurityConfiguration) {
	cr.m.Store(sc.Host, sc)
}

// GetSecurityConfiguration returns the stored configuration for the given host, returning
// nil if not found.
func (cr *CertificateRepository) GetSecurityConfiguration(host string) *SecurityConfiguration {
	if secConf, loaded := cr.m.Load(host); loaded {
		switch secConf.(type) {
		case *SecurityConfiguration:
			return secConf.(*SecurityConfiguration)
		}
	}
	return nil
}

// RemoveSecurityConfiguration resets the security configuration for the host, using
// the default security configuration instead.
func (cr *CertificateRepository) RemoveSecurityConfiguration(host string) {
	cr.m.Delete(host)
}

// SecurityConfiguration holds a host-specific configuration for the
// rules to use when verifying a TLS handshake.
type SecurityConfiguration struct {
	Host           string // e.g. google.com
	TrustPublicPKI bool
	intermediates  *x509.CertPool
}

// NewSecurityConfiguration creates a new configuration object for the given host.
// Must call CertficateRepository.AddSecurityConfiguration() for it to take effect.
func NewSecurityConfiguration(host string, trustPublicPKI bool) *SecurityConfiguration {
	secConf := &SecurityConfiguration{
		Host:           host,
		TrustPublicPKI: trustPublicPKI,
		intermediates:  x509.NewCertPool(),
	}
	return secConf
}

// AddIntermediatePEM pins the intermediate certificate(s) (in PEM format),
// adding them to the list of verified certificates for the host in this
// configuration.
func (sc *SecurityConfiguration) AddIntermediatePEM(pem []byte) error {
	ok := sc.intermediates.AppendCertsFromPEM(pem)
	if !ok {
		return errInvalidCertificate
	}
	return nil
}

// AddIntermediateASN1 pins the intermediate certificate (in ASN1 DER format),
// adding it to the list of verified certificates for the host in this
// configuration.
func (sc *SecurityConfiguration) AddIntermediateASN1(asn1 []byte) error {
	cert, err := x509.ParseCertificate(asn1)
	if err != nil {
		return err
	}
	sc.intermediates.AddCert(cert)
	return nil
}

// ResetPinning removes all intermediate certs and resets TrustSystemRoots to true.
func (sc *SecurityConfiguration) ResetPinning() {
	sc.intermediates = x509.NewCertPool()
	sc.TrustPublicPKI = true
}

func createTLSConfig() *tls.Config {
	return &tls.Config{
		VerifyConnection: func(cs tls.ConnectionState) error {
			opts := x509.VerifyOptions{
				DNSName:       cs.ServerName,
				Intermediates: x509.NewCertPool(),
			}

			host := getHostnameFromDNSName(cs.ServerName)

			sc := certRepo.GetSecurityConfiguration(host)
			if sc == nil {
				sc = certRepo.GetDefaultConfiguration()
			}

			if sc.TrustPublicPKI || len(sc.intermediates.Subjects()) == 0 {
				for _, cert := range cs.PeerCertificates[1:] {
					opts.Intermediates.AddCert(cert)
				}
			} else {
				opts.Intermediates = sc.intermediates
			}

			_, err := cs.PeerCertificates[0].Verify(opts)
			return err
		},
	}
}

// getHostnameFromDNSName returns the host name used as the key
// in the certificate repo.
func getHostnameFromDNSName(dnsName string) string {
	fields := strings.Split(dnsName, ".")
	if len(fields) == 0 {
		return dnsName
	}
	if fields[0] == "www" || fields[0] == "*" {
		return strings.Join(fields[1:], ".")
	}
	return dnsName
}
