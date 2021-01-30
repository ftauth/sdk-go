package ftauth

import (
	"crypto/rsa"
	"net/http"
	"net/url"
	"time"

	"github.com/ftauth/ftauth/pkg/jwt"
	"github.com/google/uuid"
)

// createDPoPToken creates and signs a DPoP token for an HTTP request.
func (c *Client) createDPoPToken(req *http.Request) (string, error) {
	publicKey := c.privateKey.PublicKey.(*rsa.PublicKey)
	jwk, err := jwt.NewJWKFromRSAPublicKey(publicKey)
	if err != nil {
		return "", err
	}

	jwtID, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}

	header := &jwt.Header{
		Type:      jwt.TypeDPoP,
		Algorithm: jwt.AlgorithmHMACSHA256,
		JWK:       jwk,
	}

	// Strip query and fragments for HTTPURI
	uri := req.URL
	htu := url.URL{
		Scheme: uri.Scheme,
		Host:   uri.Host,
		Path:   uri.Path,
	}
	claims := &jwt.Claims{
		JwtID:      jwtID.String(),
		HTTPMethod: req.Method,
		HTTPURI:    htu.String(),
		IssuedAt:   time.Now().UTC().Unix(),
	}

	token := &jwt.Token{
		Header: header,
		Claims: claims,
	}
	return token.Encode(c.privateKey)
}
