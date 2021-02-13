package ftauthinternal

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha256"
	"io"
	"math/rand"
	"strings"

	"github.com/ftauth/ftauth/pkg/util/base64url"
)

const characterSet = `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~`

func generateCodeChallenge() (string, string) {
	const N = 128
	numChars := len(characterSet)
	sb := new(strings.Builder)
	for i := 0; i < N; i++ {
		rIdx := rand.Intn(numChars)
		sb.WriteByte(characterSet[rIdx])
	}
	s := sb.String()
	hash := sha256.Sum256([]byte(s))
	return s, base64url.Encode(hash[:])
}

func generateState() (string, error) {
	r := crand.Reader
	var b bytes.Buffer
	_, err := io.CopyN(&b, r, 16)
	if err != nil {
		return "", err
	}
	return base64url.Encode(b.Bytes()), nil
}
