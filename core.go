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

package oauth22

// AbstractUser is an abstract type representing the current user in the system.
type AbstractUser interface{}

// Client represents a known client application using this OAuth2 server to authenticate.
//
// Related RFC topics:
// https://tools.ietf.org/html/rfc6749#section-1.1
// https://tools.ietf.org/html/rfc6749#section-2
type Client struct {
	ID           string
	Secret       string
	Name         string
	RedirectURI  string
	Confidential bool
	Internal     bool
}

// Init
// TODO(divoxx): Remove this
func (c *Client) Init() error {
	return c.generateCredentials()
}

// generateCredentials securely generate and initialize the Client's ID and Secret.
func (c *Client) generateCredentials() error {
	var err error

	c.ID, err = secureToken(32)
	if err != nil {
		return err
	}

	c.Secret, err = secureToken(32)
	if err != nil {
		return err
	}

	return nil
}

// UserAuthorization represents an explicit authorization given by the user to a specific client application.
//
// Related RFC topics:
// https://tools.ietf.org/html/rfc6749#section-4.1
// https://tools.ietf.org/html/rfc6749#section-4.2
type UserAuthorization struct {
	Client       Client
	Scope        []string
	RefreshToken []byte
}

// AccessToken represents an OAuth2 Access Token issued for an application.
//
// Related RFC topics:
// https://tools.ietf.org/html/rfc6749#section-1.1
// https://tools.ietf.org/html/rfc6749#section-1.4
type AccessToken struct {
	Client        Client
	Authorization UserAuthorization

	Token        string
	ExpiresIn    int64
	RefreshToken string
	Scope        string
}
