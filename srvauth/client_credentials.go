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

package srvauth

import (
	"net/url"
	"strings"

	"github.com/gostack/oauth22"
	"github.com/gostack/option"
)

type ClientCredentials struct{}

func (c ClientCredentials) ResponseType() (option.String, AuthorizationResponseType) {
	return option.NoneString(), nil
}

func (s ClientCredentials) GrantType() (option.String, TokenGrantType) {
	return option.SomeString("client_credentials"), clientCredentialsGrantType{}
}

type clientCredentialsGrantType struct{}

func (g clientCredentialsGrantType) IssueToken(c oauth22.Client, params url.Values) (*oauth22.AccessToken, error) {
	scopes := strings.Split(params.Get("scope"), " ")
	return oauth22.NewAccessToken(c, scopes)
}
