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

// Client is the interface implemented by all Keycloak clients.
type Client interface {
	Client(ctx context.Context, realm Realm, clientID ClientID) (*ClientRepresentation, error)
	ClientRoles(ctx context.Context, realm Realm, clientID ClientID) ([]*RoleRepresentation, error)
	ClientSecret(ctx context.Context, realm Realm, clientID ClientID) (*CredentialRepresentation, error)
	Clients(ctx context.Context, realm Realm, clientsQuery *ClientsQuery) ([]*PartialClientRepresentation, error)
	CreateClient(ctx context.Context, realm Realm, client *ClientRepresentation) (ClientID, error)
	CreateGroup(ctx context.Context, realm Realm, group *GroupRepresentation) (GroupID, error)
	CreateUser(ctx context.Context, realm Realm, user *UserRepresentation) (UserID, error)
	DeleteClient(ctx context.Context, realm Realm, clientID ClientID) error
	GenerateNewClientSecret(ctx context.Context, realm Realm, clientID ClientID) (*CredentialRepresentation, error)
	Group(ctx context.Context, realm Realm, groupID GroupID) (*GroupRepresentation, error)
	Groups(ctx context.Context, realm Realm, groupsQuery *GroupsQuery) ([]*PartialGroupRepresentation, error)
	UpdateClient(ctx context.Context, realm Realm, client *ClientRepresentation) error
	User(ctx context.Context, realm Realm, userID UserID) (*UserRepresentation, error)
	UserAddGroup(ctx context.Context, realm Realm, userID UserID, groupID GroupID) error
	UserGroups(ctx context.Context, realm Realm, userID UserID) ([]GroupRepresentation, error)
	UserRemoveGroup(ctx context.Context, realm Realm, userID UserID, groupID GroupID) error
	Users(ctx context.Context, realm Realm, usersQuery *UsersQuery) ([]*PartialUserRepresentation, error)
}

// A ClientsQuery contains options for querying clients.
type ClientsQuery struct {
	ClientID     string
	ViewableOnly bool
}

// A GroupsQuery contains options for querying groups.
type GroupsQuery struct {
	First  int
	Max    int
	Search string
}

// A UsersQuery contains options for querying users.
type UsersQuery struct {
	BriefRepresentation bool
	Email               string
	First               int
	FirstName           string
	LastName            string
	Max                 int
	Search              string
	Username            string
}
