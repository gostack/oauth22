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

	"github.com/gostack/option"
)

// ClientCredentials implement the standard OAuth2 Client Credentials grant type as described by
// https://tools.ietf.org/html/rfc6749#section-4.4
type ClientCredentials struct{}

// ResponseType simply registers a nil AuthorizationResponseType for ClientCredentials
func (c ClientCredentials) ResponseType() (option.String, AuthorizationResponseType) {
	return option.NoneString(), nil
}

// GrantType register the client_credentials grant type for ClientCredentials.
func (s ClientCredentials) GrantType() (option.String, TokenGrantType) {
	return option.SomeString("client_credentials"), ClientCredentialsGrantType{}
}

// ClientCredentialsGranType implements the AuthorizationResponseType to allow for OAuth2's
// client_credentials grant type.
type ClientCredentialsGrantType struct{}

// IssueToken issues a new token for the requesting client as defined by the client credential grant
// type.
func (g ClientCredentialsGrantType) IssueToken(c *Client, params url.Values) (*AccessToken, error) {
	scopes := strings.Split(params.Get("scope"), " ")
	return NewAccessToken(c, scopes)
}
