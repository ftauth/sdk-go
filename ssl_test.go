package ftauth

import (
	"crypto/x509"
	"io/ioutil"
	"log"
	"net/http"
	"path"
	"testing"

	"github.com/stretchr/testify/require"
)

type certificateChain struct {
	host         string
	leaf         *x509.Certificate
	intermediate *x509.Certificate
	root         *x509.Certificate
}

func loadCerts(host string) *certificateChain {
	testdata := path.Join("testdata", host)
	leafCertASN1, err := ioutil.ReadFile(path.Join(testdata, "leaf.cer"))
	if err != nil {
		log.Fatalln("Error reading leaf cert: ", err)
	}
	leafCert, err := x509.ParseCertificate(leafCertASN1)
	if err != nil {
		log.Fatalln("Error parsing leaf cert: ", err)
	}
	intCertASN1, err := ioutil.ReadFile(path.Join(testdata, "int.cer"))
	if err != nil {
		log.Fatalln("Error reading int cert: ", err)
	}
	intCert, err := x509.ParseCertificate(intCertASN1)
	if err != nil {
		log.Fatalln("Error parsing int cert: ", err)
	}
	rootCertASN1, err := ioutil.ReadFile(path.Join(testdata, "root.cer"))
	if err != nil {
		log.Fatalln("Error reading root cert: ", err)
	}
	rootCert, err := x509.ParseCertificate(rootCertASN1)
	if err != nil {
		log.Fatalln("Error parsing root cert: ", err)
	}

	return &certificateChain{
		host:         host,
		leaf:         leafCert,
		intermediate: intCert,
		root:         rootCert,
	}
}

func TestCreateTLSConfig(t *testing.T) {
	googleCertChain := loadCerts("google")
	amazonCertChain := loadCerts("amazon")

	tlsConfig := createTLSConfig()
	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	tt := []struct {
		name         string
		setupConfigs func()
		requestURL   string
		wantErr      bool
	}{
		{
			name:         "default trust public PKI",
			setupConfigs: func() {},
			requestURL:   "https://google.com",
			wantErr:      false,
		},
		{
			name: "no trust public PKI, valid cert, valid host",
			setupConfigs: func() {
				conf := NewSecurityConfiguration("google.com", false)
				conf.AddIntermediateASN1(googleCertChain.intermediate.Raw)

				certRepo.AddSecurityConfiguration(conf)
			},
			requestURL: "https://google.com",
			wantErr:    false,
		},
		{
			name: "no trust public PKI, valid cert, valid host",
			setupConfigs: func() {
				azConf := NewSecurityConfiguration("amazon.com", false)
				azConf.AddIntermediateASN1(amazonCertChain.intermediate.Raw)

				certRepo.AddSecurityConfiguration(azConf)
			},
			requestURL: "https://amazon.com",
			wantErr:    false,
		},
		{
			name: "trust public PKI, valid cert, valid host",
			setupConfigs: func() {
				conf := NewSecurityConfiguration("google.com", true)
				conf.AddIntermediateASN1(googleCertChain.intermediate.Raw)

				certRepo.AddSecurityConfiguration(conf)
			},
			requestURL: "https://google.com",
			wantErr:    false,
		},
		{
			name: "trust public PKI, valid cert, valid host",
			setupConfigs: func() {
				azConf := NewSecurityConfiguration("amazon.com", true)
				azConf.AddIntermediateASN1(amazonCertChain.intermediate.Raw)

				certRepo.AddSecurityConfiguration(azConf)
			},
			requestURL: "https://amazon.com",
			wantErr:    false,
		},
	}

	for _, test := range tt {
		t.Run(test.name, func(t *testing.T) {
			test.setupConfigs()

			_, err := client.Get(test.requestURL)
			if test.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})

		// Clear the certificate repository
		certRepo = &CertificateRepository{}
	}
}

func TestGetHostnameFromDNSName(t *testing.T) {
	tt := []struct {
		dnsName  string
		hostname string
	}{
		{
			dnsName:  "www.google.com",
			hostname: "google.com",
		},
		{
			dnsName:  "google.com",
			hostname: "google.com",
		},
		{
			dnsName:  "*.google.com",
			hostname: "google.com",
		},
		{
			dnsName:  "",
			hostname: "",
		},
	}

	for _, test := range tt {
		t.Run(test.dnsName, func(t *testing.T) {
			require.Equal(t, test.hostname, getHostnameFromDNSName(test.dnsName))
		})
	}
}
