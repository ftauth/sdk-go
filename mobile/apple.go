package ftauthinternal

import (
	"errors"
	"strings"
)

// AppleCredentialType is the means through which the user authenticating using
// Sign In With Apple.
type AppleCredentialType string

// Supported Apple credential types.
const (
	AppleCredentialTypeAppleID  AppleCredentialType = "apple_id" // Apple ID
	AppleCredentialTypePassword AppleCredentialType = "password" // Username and password
)

// SignInWithAppleData holds the data we can expect to receive back from iOS
// after a successful login call, broken out by credential type.
type SignInWithAppleData struct {
	CredentialType AppleCredentialType

	// AppleCredentialTypeAppleID
	UserID         string
	AuthCode       []byte
	Scopes         []string
	IDToken        []byte
	Email          string
	FirstName      string
	LastName       string
	RealUserStatus int

	// AppleCredentialTypePassword
	Username string
	Password string
}

// NewSignInWithAppleIDData returns a data object for the Apple ID flow.
func NewSignInWithAppleIDData(
	UserID string,
	AuthCode []byte,
	Scopes string,
	IDToken []byte,
	Email string,
	FirstName string,
	LastName string,
	RealUserStatus int,
) *SignInWithAppleData {
	return &SignInWithAppleData{
		CredentialType: AppleCredentialTypeAppleID,
		UserID:         UserID,
		AuthCode:       AuthCode,
		Scopes:         strings.Split(Scopes, ","),
		IDToken:        IDToken,
		Email:          Email,
		FirstName:      FirstName,
		LastName:       LastName,
		RealUserStatus: RealUserStatus,
	}
}

// NewSignInWithApplePasswordData returns a data object for the password flow.
func NewSignInWithApplePasswordData(username, password string) *SignInWithAppleData {
	return &SignInWithAppleData{
		CredentialType: AppleCredentialTypePassword,
		Username:       username,
		Password:       password,
	}
}

// Valid returns whether or not the data is valid, for ensuring
// we receive valid data from the mobile side.
func (data *SignInWithAppleData) Valid() error {
	switch data.CredentialType {
	case AppleCredentialTypeAppleID:
		if data.UserID == "" {
			return errors.New("missing user ID")
		}
		if len(data.AuthCode) == 0 {
			return errors.New("missing auth code")
		}
	case AppleCredentialTypePassword:
		if data.Username == "" {
			return errors.New("missing username")
		}
		if data.Password == "" {
			return errors.New("missing password")
		}
	}
	return nil
}

// SignInWithApple is the callback for the iOS13+ Sign In With Apple flow.
// Basically, it's the reverse of the typical flow, since the OAuth flow
// is handled by Apple, then we store a copy of the information on our end
// and convert it into a UserData object via the server.
type SignInWithApple interface {
	SignInWithApple(user *SignInWithAppleData) (*UserData, error)
}
