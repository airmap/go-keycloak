// Copyright 2019 AirMap Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package keycloak

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2/clientcredentials"
)

// Ensure that RESTClient implements Client.
var _ Client = &RESTClient{}

func TestNewRESTClient(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options []RESTClientOption
		want    *RESTClient
	}{
		{
			name: "password_auth",
			options: []RESTClientOption{
				PasswordAuth("user", "pass"),
			},
			want: &RESTClient{
				baseURL:   "http://localhost:8080/auth",
				userAgent: "github.com/airmap/go-keycloak",
				config: clientcredentials.Config{
					ClientID: "admin-cli",
					TokenURL: "http://localhost:8080/auth/realms/master/protocol/openid-connect/token",
					EndpointParams: url.Values{
						"grant_type": {"password"},
						"username":   {"user"},
						"password":   {"pass"},
					},
				},
			},
		},
		{
			name: "client_credentials_auth",
			options: []RESTClientOption{
				ClientCredentialsAuth("secret"),
			},
			want: &RESTClient{
				baseURL:   "http://localhost:8080/auth",
				userAgent: "github.com/airmap/go-keycloak",
				config: clientcredentials.Config{
					ClientID:     "admin-cli",
					ClientSecret: "secret",
					TokenURL:     "http://localhost:8080/auth/realms/master/protocol/openid-connect/token",
				},
			},
		},
		{
			name: "client_credentials_auth_with_admin_realm",
			options: []RESTClientOption{
				AdminRealm("airmap"),
				ClientCredentialsAuth("secret"),
			},
			want: &RESTClient{
				baseURL:   "http://localhost:8080/auth",
				userAgent: "github.com/airmap/go-keycloak",
				config: clientcredentials.Config{
					ClientID:     "admin-cli",
					ClientSecret: "secret",
					TokenURL:     "http://localhost:8080/auth/realms/airmap/protocol/openid-connect/token",
				},
			},
		},
		{
			name: "airmap_test",
			options: []RESTClientOption{
				AdminRealm("airmap"),
				AdminClientID("admin"),
				ClientCredentialsAuth("secret"),
				BaseURL("https://test.auth.airmap.com"),
			},
			want: &RESTClient{
				baseURL:   "https://test.auth.airmap.com",
				userAgent: "github.com/airmap/go-keycloak",
				config: clientcredentials.Config{
					ClientID:     "admin",
					ClientSecret: "secret",
					TokenURL:     "https://test.auth.airmap.com/realms/airmap/protocol/openid-connect/token",
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := NewRESTClient(tc.options...)
			assert.Equal(t, got, tc.want, "values differ")
		})
	}
}

func TestRESTClientURLStr(t *testing.T) {
	c := NewRESTClient()
	realm := Realm("test-realm")
	userID := UserID("test-user")
	groupID := GroupID("test-group")
	want := "http://localhost:8080/auth/admin/realms/test-realm/users/test-user/groups/test-group"
	if got := c.urlStr("admin", "realms", realm, "users", userID, "groups", groupID); got != want {
		t.Errorf("c.urlStr(...) == %q, want %q", got, want)
	}
}
