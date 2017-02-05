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

package authzsrv_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gostack/oauth22/authzsrv"
)

// TestUnsupportedGrantType ensures that clients sending an unsupported grant type will receive the
// proper error response.
func TestUnsupportedGrantType(t *testing.T) {
	srvURL, teardown, client := setupTestServer(t, []authzsrv.Strategy{
		authzsrv.ClientCredentials{},
	})
	defer teardown()

	resp := doTokenRequest(t, srvURL, &client, "unsupported", "basic email")
	defer resp.Body.Close()

	verifyResponseErr(t, resp, authzsrv.ErrUnsupportedGrantType)
}

// TestClientCredentialsSuccessful verifies the happy path for the client credential flow,
// ensuring a proper access token is issued at the end.
func TestClientCredentialsSuccessful(t *testing.T) {
	srvURL, teardown, client := setupTestServer(t, []authzsrv.Strategy{
		authzsrv.ClientCredentials{},
	})
	defer teardown()

	resp := doTokenRequest(t, srvURL, &client, "client_credentials", "basic email")
	defer resp.Body.Close()

	verifyResponseOK(t, resp)
}

// TestClientCredentialsInvalidCredentials ensures the client credentials grant type properly
// rejects when the credentials are not valid.
func TestClientCredentialsInvalidCredentials(t *testing.T) {
	srvURL, teardown, client := setupTestServer(t, []authzsrv.Strategy{
		authzsrv.ClientCredentials{},
	})
	defer teardown()

	client.Secret = []byte("INVALID")

	resp := doTokenRequest(t, srvURL, &client, "client_credentials", "basic email")
	defer resp.Body.Close()

	verifyResponseErr(t, resp, authzsrv.ErrInvalidClient)
}

// setupTestServer builds the server configuration on top of httptest in order to run requests
// against it. It returns the URL for the test server instance and a teardown function.
func setupTestServer(t *testing.T, strategies []authzsrv.Strategy) (string, func(), authzsrv.Client) {
	c := authzsrv.Client{Name: "3rd party client"}
	if err := c.GenerateCredentials(); err != nil {
		t.Fatal(err)
	}

	persistence := authzsrv.NewInMemoryPersistence()
	persistence.RegisterClient(&c)

	srv := authzsrv.NewServer(persistence)

	for _, st := range strategies {
		srv.RegisterStrategy(st)
	}

	httpSrv := httptest.NewServer(srv)
	return httpSrv.URL, httpSrv.Close, c
}

// doTokenRequest performs a request to the token endpoint with the provided grantType and scope
func doTokenRequest(t *testing.T, srvURL string, client *authzsrv.Client, grantType, scope string) *http.Response {
	req, err := http.NewRequest("POST", srvURL+"/token", strings.NewReader(url.Values{
		"grant_type": []string{grantType},
		"scope":      []string{scope},
	}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client.ID.String(), client.Secret.String())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("%#v\n", resp)
	return resp
}

// verifyResponseOK verifies that the http response is a successfull one.
func verifyResponseOK(t *testing.T, resp *http.Response) {
	if resp.StatusCode != 200 {
		t.Fatalf("unexpected status code: %d (expected %d)", resp.StatusCode, 200)
	}

	tokenResponse := struct {
		AccessToken  string `json:"access_token"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
	}{}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		t.Fatal(err)
	}

	if tokenResponse.AccessToken == "" {
		t.Fatal("access token response does not contain a token")
	}
}

// verifyResponseErr verifies that the http response is a error one
func verifyResponseErr(t *testing.T, resp *http.Response, expectedErr authzsrv.OAuth2Error) {
	if resp.StatusCode != expectedErr.Code {
		t.Fatalf("unexpected status code: %d (expected %d)", resp.StatusCode, expectedErr.Code)
	}

	errResponse := struct {
		Error     string `json:"error"`
		ErrorDesc string `json:"error_description"`
	}{}
	if err := json.NewDecoder(resp.Body).Decode(&errResponse); err != nil {
		t.Fatal(err)
	}

	if errResponse.Error != expectedErr.ID {
		t.Fatal("unexpected error %s (expected %s)", errResponse.Error, expectedErr.ID)
	}
}
