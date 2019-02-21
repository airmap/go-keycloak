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
	"context"
)

// A RealmClient wraps a Client for a specific realm.
type RealmClient struct {
	client Client
	realm  Realm
}

// NewRealmClient returns a new RealmClient.
func NewRealmClient(client Client, realm Realm) *RealmClient {
	return &RealmClient{
		client: client,
		realm:  realm,
	}
}

// Client wraps Client.
func (r *RealmClient) Client(ctx context.Context, clientID ClientID) (*ClientRepresentation, error) {
	return r.client.Client(ctx, r.realm, clientID)
}

// ClientRoles wraps ClientRoles.
func (r *RealmClient) ClientRoles(ctx context.Context, clientID ClientID) ([]*RoleRepresentation, error) {
	return r.client.ClientRoles(ctx, r.realm, clientID)
}

// ClientSecret wraps ClientSecret.
func (r *RealmClient) ClientSecret(ctx context.Context, clientID ClientID) (*CredentialRepresentation, error) {
	return r.client.ClientSecret(ctx, r.realm, clientID)
}

// Clients wraps Clients.
func (r *RealmClient) Clients(ctx context.Context, clientsQuery *ClientsQuery) ([]*PartialClientRepresentation, error) {
	return r.client.Clients(ctx, r.realm, clientsQuery)
}

// CreateClient wraps CreateClient.
func (r *RealmClient) CreateClient(ctx context.Context, client *ClientRepresentation) (ClientID, error) {
	return r.client.CreateClient(ctx, r.realm, client)
}

// CreateGroup wraps CreateGroup.
func (r *RealmClient) CreateGroup(ctx context.Context, group *GroupRepresentation) (GroupID, error) {
	return r.client.CreateGroup(ctx, r.realm, group)
}

// CreateUser wraps CreateUser.
func (r *RealmClient) CreateUser(ctx context.Context, user *UserRepresentation) (UserID, error) {
	return r.client.CreateUser(ctx, r.realm, user)
}

// DeleteClient wraps DeleteClient.
func (r *RealmClient) DeleteClient(ctx context.Context, clientID ClientID) error {
	return r.client.DeleteClient(ctx, r.realm, clientID)
}

// GenerateNewClientSecret wraps GenerateNewClientSecret.
func (r *RealmClient) GenerateNewClientSecret(ctx context.Context, clientID ClientID) (*CredentialRepresentation, error) {
	return r.client.GenerateNewClientSecret(ctx, r.realm, clientID)
}

// Group wraps Group.
func (r *RealmClient) Group(ctx context.Context, groupID GroupID) (*GroupRepresentation, error) {
	return r.client.Group(ctx, r.realm, groupID)
}

// Groups wraps Groups.
func (r *RealmClient) Groups(ctx context.Context, groupsQuery *GroupsQuery) ([]*PartialGroupRepresentation, error) {
	return r.client.Groups(ctx, r.realm, groupsQuery)
}

// UpdateClient wraps UpdateClient.
func (r *RealmClient) UpdateClient(ctx context.Context, client *ClientRepresentation) error {
	return r.client.UpdateClient(ctx, r.realm, client)
}

// User wraps User.
func (r *RealmClient) User(ctx context.Context, userID UserID) (*UserRepresentation, error) {
	return r.client.User(ctx, r.realm, userID)
}

// UserAddGroup wraps UserAddGroup.
func (r *RealmClient) UserAddGroup(ctx context.Context, userID UserID, groupID GroupID) error {
	return r.client.UserAddGroup(ctx, r.realm, userID, groupID)
}

// UserGroups wraps UserGroups.
func (r *RealmClient) UserGroups(ctx context.Context, userID UserID) ([]GroupRepresentation, error) {
	return r.client.UserGroups(ctx, r.realm, userID)
}

// UserRemoveGroup wraps UserRemoveGroup.
func (r *RealmClient) UserRemoveGroup(ctx context.Context, userID UserID, groupID GroupID) error {
	return r.client.UserRemoveGroup(ctx, r.realm, userID, groupID)
}

// Users wraps Users.
func (r *RealmClient) Users(ctx context.Context, usersQuery *UsersQuery) ([]*PartialUserRepresentation, error) {
	return r.client.Users(ctx, r.realm, usersQuery)
}
