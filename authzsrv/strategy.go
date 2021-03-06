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
	"net/http"
	"net/url"

	"github.com/gostack/option"
)

// Strategy wraps the two optional interfaces that constitutes a OAuth2 strategies.
// Strategies should implement at least one of the interfaces.
type Strategy interface {
	ResponseType(p Persistence) (option.String, AuthorizationResponseType)
	GrantType(p Persistence) (option.String, TokenGrantType)
}

// AuthorizationResponseType is the interface that represents a valid OAuth2 response type, used by the authorization endpoint.
type AuthorizationResponseType interface {
	Confirm(ar *UserAuthorizationRequest, w http.ResponseWriter) error
	Authorize(ar *UserAuthorizationRequest) (*UserAuthorization, error)
}

// TokenGrantType is the interface that represents a valid OAuth2 grant type, used by the token endpoint.
type TokenGrantType interface {
	IssueToken(c *Client, params url.Values) (*AccessToken, error)
}
