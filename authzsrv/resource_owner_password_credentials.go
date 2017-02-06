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
	"net/url"
	"strings"

	"github.com/gostack/oauth22/security"
	"github.com/gostack/option"
)

// ResourceOwnerPasswordCredentials implement the standard OAuth2 Resource Owner Password
// Credentials grant type as described by https://tools.ietf.org/html/rfc6749#section-4.3
type ResourceOwnerPasswordCredentials struct{}

// ResponseType simply registers a nil AuthorizationResponseType for
// ResourceOwnerPasswordCredentials
func (c ResourceOwnerPasswordCredentials) ResponseType(p Persistence) (option.String, AuthorizationResponseType) {
	return option.NoneString(), nil
}

// GrantType register the client_credentials grant type for ResourceOwnerPasswordCredentials.
func (s ResourceOwnerPasswordCredentials) GrantType(p Persistence) (option.String, TokenGrantType) {
	return option.SomeString("password"), ResourceOwnerPasswordCredentialsGrantType{p}
}

// ResourceOwnerPasswordCredentialsGrantType implements the AuthorizationResponseType to allow for OAuth2's
// client_credentials grant type.
type ResourceOwnerPasswordCredentialsGrantType struct {
	LoaderUserFromUsername
}

// IssueToken issues a new token for the requesting client as defined by the client credential grant
// type.
func (g ResourceOwnerPasswordCredentialsGrantType) IssueToken(c *Client, params url.Values) (*AccessToken, error) {
	var (
		username = params.Get("username")
		password = params.Get("password")
		scopes   = strings.Split(params.Get("scope"), " ")
	)

	if username == "" || password == "" {
		return nil, ErrInvalidRequest
	}

	u, err := g.LoadUserFromUsername(username)
	if err != nil {
		return nil, ErrServerError
	}

	if !security.Compare(u.Password, []byte(password)) {
		return nil, ErrAccessDenied
	}

	return NewAccessToken(c, u, scopes)
}
