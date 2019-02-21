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

package keycloak_test

import (
	"context"

	"github.com/airmap/go-keycloak"
)

func ExampleNewRESTClient_clientCredentialsAuth() {
	var (
		adminClientID     = keycloak.DefaultAdminClientID
		adminClientSecret = "admin-client-secret"
		adminRealm        = keycloak.DefaultAdminRealm
		baseURL           = keycloak.DefaultBaseURL
	)
	restClient := keycloak.NewRESTClient(
		keycloak.AdminClientID(adminClientID),
		keycloak.ClientCredentialsAuth(adminClientSecret),
		keycloak.BaseURL(baseURL),
		keycloak.AdminRealm(adminRealm),
	)
	_ = restClient
}

func ExampleNewRESTClient_passwordAuth() {
	var (
		adminClientID = keycloak.DefaultAdminClientID
		adminRealm    = keycloak.DefaultAdminRealm
		baseURL       = keycloak.DefaultBaseURL
		username      = "username"
		password      = "password"
	)
	restClient := keycloak.NewRESTClient(
		keycloak.AdminClientID(adminClientID),
		keycloak.BaseURL(baseURL),
		keycloak.AdminRealm(adminRealm),
		keycloak.PasswordAuth(username, password),
	)
	_ = restClient
}

func ExampleRealmClient_Users() {
	var (
		restClient  = keycloak.NewRESTClient( /* options... */ )
		realm       = keycloak.Realm("example")
		realmClient = keycloak.NewRealmClient(restClient, realm)
	)
	ctx := context.Background()
	var users []*keycloak.PartialUserRepresentation
	first := 0
	for {
		// Break when ctx is canceled.
		select {
		case <-ctx.Done():
			break
		default:
		}
		// Load the next page of users.
		usersPage, err := realmClient.Users(ctx, &keycloak.UsersQuery{
			First: first,
		})
		if err != nil {
			panic(err)
		}
		// Break when there are no more users.
		if len(usersPage) == 0 {
			break
		}
		users = append(users, usersPage...)
		first += len(usersPage)
	}
	_ = users
}
