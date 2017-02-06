/*
Copyright 2015 Rodrigo Rafael Monti Kochenburger

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package authzsrv

import (
	"encoding/base64"
	"time"

	"github.com/satori/go.uuid"

	"github.com/gostack/oauth22/security"
)

// User is an type representing the current user in the system.
type User struct {
	Username string
	Password []byte
}

// Secret is a seq of bytes that knows how to serialize itself
type Secret []byte

func (s Secret) String() string {
	str, err := s.MarshalText()
	if err != nil {
		return ""
	}

	return string(str)
}

func (s Secret) MarshalText() ([]byte, error) {
	// Calculates the number of bytes necessary for the base64
	// representation and pre-allocate it to avoid multiple allocations.
	b := make([]byte, base64.RawURLEncoding.EncodedLen(len(s)))
	base64.RawURLEncoding.Encode(b, s)
	return b, nil
}

func (s *Secret) UnmarshalText(text []byte) error {
	// Calculates the number of bytes necessary for the base64
	// to be represented and pre-allocate it to avoid multiple allocations.
	*s = make([]byte, base64.RawURLEncoding.DecodedLen(len(text)))
	_, err := base64.RawURLEncoding.Decode(*s, text)
	return err
}

// Client represents a known client application using this OAuth2 server to authenticate.
//
// Related RFC topics:
// https://tools.ietf.org/html/rfc6749#section-1.1
// https://tools.ietf.org/html/rfc6749#section-2
type Client struct {
	ID           uuid.UUID
	Secret       Secret
	Name         string
	RedirectURI  string
	Confidential bool
	Internal     bool
}

// GenerateCredentials securely generate and initialize the Client's ID and Secret.
func (c *Client) GenerateCredentials() error {
	var err error

	c.ID = uuid.NewV4()
	c.Secret, err = security.Random(128)
	if err != nil {
		return err
	}

	return nil
}

// UserAuthorizationRequest represents a request for a UserAuthorization
type UserAuthorizationRequest struct {
	Client Client
	Scope  []string
}

// UserAuthorization represents an explicit authorization given by the user to a specific client application.
//
// Related RFC topics:
// https://tools.ietf.org/html/rfc6749#section-4.1
// https://tools.ietf.org/html/rfc6749#section-4.2
type UserAuthorization struct {
	UserAuthorizationRequest
	RefreshToken []byte
}

// AccessToken represents an OAuth2 Access Token issued for an application.
//
// Related RFC topics:
// https://tools.ietf.org/html/rfc6749#section-1.1
// https://tools.ietf.org/html/rfc6749#section-1.4
type AccessToken struct {
	Client       *Client       `json:"-"`
	User         *User         `json:"-"`
	Scopes       []string      `json:"-"`
	Token        []byte        `json:"access_token"`
	ExpiresIn    time.Duration `json:"expires_in"`
	RefreshToken string        `json:"refresh_token,omitempty"`
}

// NewAccessToken creates a new AccessToken with the provided information and sensible defaults.
func NewAccessToken(c *Client, u *User, scopes []string) (*AccessToken, error) {
	t, err := security.Random(256)
	if err != nil {
		return nil, err
	}

	at := AccessToken{
		Client:    c,
		User:      u,
		Token:     t,
		Scopes:    scopes,
		ExpiresIn: (24 * time.Hour) * 15,
	}

	return &at, nil
}
