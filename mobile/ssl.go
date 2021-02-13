package ftauthinternal

import ftauth "github.com/ftauth/sdk-go"

// CertificateRepository holds a map of hosts to certificate pools
// for use with TLS handshake verification (i.e. certificate pinning).
type CertificateRepository ftauth.CertificateRepository

// SecurityConfiguration holds a host-specific configuration for the
// rules to use when verifying a TLS handshake.
type SecurityConfiguration ftauth.SecurityConfiguration

// GetCertificateRepository returns the main certificate repo for adding/removing
// security configurations.
func GetCertificateRepository() *CertificateRepository {
	return (*CertificateRepository)(ftauth.GetCertificateRepository())
}

// GetDefaultConfiguration returns the default security configuration, i.e. the configuration
// used when a server's configuration has not been explicitly set.
func (cr *CertificateRepository) GetDefaultConfiguration() *SecurityConfiguration {
	return (*SecurityConfiguration)((*ftauth.CertificateRepository)(cr).GetDefaultConfiguration())
}

// SetDefaultConfiguration sets the default security configuration, i.e. the configuration
// used when a server's configuration has not been explicitly set.
func (cr *CertificateRepository) SetDefaultConfiguration(sc *SecurityConfiguration) {
	(*ftauth.CertificateRepository)(cr).SetDefaultConfiguration((*ftauth.SecurityConfiguration)(sc))
}

// AddSecurityConfiguration configures the TLS client for request to the specified host.
func (cr *CertificateRepository) AddSecurityConfiguration(sc *SecurityConfiguration) {
	(*ftauth.CertificateRepository)(cr).AddSecurityConfiguration((*ftauth.SecurityConfiguration)(sc))
}

// GetSecurityConfiguration returns the stored configuration for the given host, returning
// nil if not found.
func (cr *CertificateRepository) GetSecurityConfiguration(host string) *SecurityConfiguration {
	return (*SecurityConfiguration)((*ftauth.CertificateRepository)(cr).GetSecurityConfiguration(host))
}

// RemoveSecurityConfiguration resets the security configuration for the host, using
// the default security configuration instead.
func (cr *CertificateRepository) RemoveSecurityConfiguration(host string) {
	(*ftauth.CertificateRepository)(cr).RemoveSecurityConfiguration(host)
}

// NewSecurityConfiguration creates a new configuration object for the given host.
// Must call CertficateRepository.AddSecurityConfiguration() for it to take effect.
func NewSecurityConfiguration(host string, trustPublicPKI bool) *SecurityConfiguration {
	secConf := ftauth.NewSecurityConfiguration(host, trustPublicPKI)
	return (*SecurityConfiguration)(secConf)
}

// AddIntermediatePEM pins the intermediate certificate(s) (in PEM format),
// adding them to the list of verified certificates for the host in this
// configuration.
func (sc *SecurityConfiguration) AddIntermediatePEM(pem []byte) error {
	return (*ftauth.SecurityConfiguration)(sc).AddIntermediatePEM(pem)
}

// AddIntermediateASN1 pins the intermediate certificate (in ASN1 DER format),
// adding it to the list of verified certificates for the host in this
// configuration.
func (sc *SecurityConfiguration) AddIntermediateASN1(asn1 []byte) error {
	return (*ftauth.SecurityConfiguration)(sc).AddIntermediateASN1(asn1)
}

// ResetPinning removes all intermediate certs and resets TrustSystemRoots to true.
func (sc *SecurityConfiguration) ResetPinning() {
	(*ftauth.SecurityConfiguration)(sc).ResetPinning()
}
