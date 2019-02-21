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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strconv"

	"golang.org/x/oauth2/clientcredentials"
)

const (
	// DefaultBaseURL is the default base URL.
	DefaultBaseURL = "http://localhost:8080/auth"

	// DefaultAdminClientID is the default admin client ID.
	DefaultAdminClientID ClientID = "admin-cli"

	// DefaultAdminRealm is the default admin realm.
	DefaultAdminRealm Realm = "master"

	// DefaultUserAgent is the default user agent.
	DefaultUserAgent = "github.com/airmap/go-keycloak"
)

// A RESTClientOption sets an option on a RESTClient.
type RESTClientOption func(*RESTClient)

// A RESTClient is a Keycloak REST client.
type RESTClient struct {
	baseURL   string
	userAgent string
	config    clientcredentials.Config
}

// An RESTError is an REST error returned by Keycloak. Keycloak does not report
// errors in a consistent format. The body can be empty, an arbitray string, or
// a JSON object, and may contain useful information for debugging.
type RESTError struct {
	Request      *http.Request
	Response     *http.Response
	ResponseBody []byte
}

// AdminClientID sets the admin client id.
func AdminClientID(adminClientID ClientID) RESTClientOption {
	return func(c *RESTClient) {
		c.config.ClientID = string(adminClientID)
	}
}

// AdminRealm sets the realm for requesting the OpenID Connect token.
func AdminRealm(adminRealm Realm) RESTClientOption {
	return func(c *RESTClient) {
		// Set the token URL without the base as we don't know the base URL yet.
		c.config.TokenURL = getTokenURLPathForRealm(adminRealm)
	}
}

// BaseURL sets the base URL.
func BaseURL(baseURL string) RESTClientOption {
	return func(c *RESTClient) {
		c.baseURL = baseURL
	}
}

// ClientCredentialsAuth authenticates with a client ID and secret.
func ClientCredentialsAuth(clientSecret string) RESTClientOption {
	return func(c *RESTClient) {
		c.config.ClientSecret = clientSecret
	}
}

// PasswordAuth authenticates with a username and password. This is only
// available if you build this library with a patched golang.org/x/oauth2
// including https://github.com/golang/oauth2/pull/363.
func PasswordAuth(username, password string) RESTClientOption {
	return func(c *RESTClient) {
		c.config.EndpointParams = url.Values{
			"grant_type": {"password"},
			"username":   {username},
			"password":   {password},
		}
	}
}

// UserAgent sets the user agent.
func UserAgent(userAgent string) RESTClientOption {
	return func(c *RESTClient) {
		c.userAgent = userAgent
	}
}

// NewRESTClient returns a new RESTClient with the given options.
func NewRESTClient(options ...RESTClientOption) *RESTClient {
	c := &RESTClient{
		baseURL:   DefaultBaseURL,
		userAgent: DefaultUserAgent,
		config: clientcredentials.Config{
			ClientID: string(DefaultAdminClientID),
			// Initially create the token URL without the base as we don't know
			// the base URL yet.
			TokenURL: getTokenURLPathForRealm(DefaultAdminRealm),
		},
	}
	for _, o := range options {
		o(c)
	}
	// Prepend the base URL to the token URL.
	c.config.TokenURL = c.baseURL + c.config.TokenURL
	return c
}

// Client returns the client with clientID in realm.
func (c *RESTClient) Client(ctx context.Context, realm Realm, clientID ClientID) (*ClientRepresentation, error) {
	urlStr := c.urlStr("admin", "realms", realm, "clients", clientID)
	req, err := c.newRequest(http.MethodGet, urlStr, nil, nil)
	if err != nil {
		return nil, err
	}
	var clientRepresentation ClientRepresentation
	if err := c.doRequest(ctx, req, &clientRepresentation); err != nil {
		return nil, err
	}
	return &clientRepresentation, nil
}

// ClientRoles returns the client's roles.
func (c *RESTClient) ClientRoles(ctx context.Context, realm Realm, clientID ClientID) ([]*RoleRepresentation, error) {
	urlStr := c.urlStr("admin", "realms", realm, "clients", clientID, "roles")
	req, err := c.newRequest(http.MethodGet, urlStr, nil, nil)
	if err != nil {
		return nil, err
	}
	var rolesRepresentation []*RoleRepresentation
	if err := c.doRequest(ctx, req, &rolesRepresentation); err != nil {
		return nil, err
	}
	return rolesRepresentation, nil
}

// ClientSecret returns the client's secret.
func (c *RESTClient) ClientSecret(ctx context.Context, realm Realm, clientID ClientID) (*CredentialRepresentation, error) {
	urlStr := c.urlStr("admin", "realms", realm, "clients", clientID, "client-secret")
	req, err := c.newRequest(http.MethodGet, urlStr, nil, nil)
	if err != nil {
		return nil, err
	}
	var credentialRepresentation CredentialRepresentation
	if err := c.doRequest(ctx, req, &credentialRepresentation); err != nil {
		return nil, err
	}
	return &credentialRepresentation, nil
}

// Clients returns a slice of clients, filtered according to the query options
// in clientsQuery.
func (c *RESTClient) Clients(ctx context.Context, realm Realm, clientsQuery *ClientsQuery) ([]*PartialClientRepresentation, error) {
	urlStr := c.urlStr("admin", "realms", realm, "clients")
	req, err := c.newRequest(http.MethodGet, urlStr, clientsQuery.values(), nil)
	if err != nil {
		return nil, err
	}
	var pcrs []*PartialClientRepresentation
	if err := c.doRequest(ctx, req, &pcrs); err != nil {
		return nil, err
	}
	return pcrs, nil
}

// CreateClient creates a new client.
func (c *RESTClient) CreateClient(ctx context.Context, realm Realm, client *ClientRepresentation) (ClientID, error) {
	urlStr := c.urlStr("admin", "realms", realm, "clients")
	req, err := c.newRequestJSON(http.MethodPost, urlStr, client)
	if err != nil {
		return "", err
	}
	clientIDStr, err := c.doCreateRequest(ctx, req)
	return ClientID(clientIDStr), err
}

// CreateGroup creates a new group.
func (c *RESTClient) CreateGroup(ctx context.Context, realm Realm, group *GroupRepresentation) (GroupID, error) {
	urlStr := c.urlStr("admin", "realms", realm, "groups")
	req, err := c.newRequestJSON(http.MethodPost, urlStr, group)
	if err != nil {
		return "", err
	}
	groupIDStr, err := c.doCreateRequest(ctx, req)
	return GroupID(groupIDStr), err
}

// CreateUser creates a new user.
func (c *RESTClient) CreateUser(ctx context.Context, realm Realm, user *UserRepresentation) (UserID, error) {
	urlStr := c.urlStr("admin", "realms", realm, "users")
	req, err := c.newRequestJSON(http.MethodPost, urlStr, user)
	if err != nil {
		return "", err
	}
	userIDStr, err := c.doCreateRequest(ctx, req)
	return UserID(userIDStr), err
}

// DeleteClient deletes client clientID in realm.
func (c *RESTClient) DeleteClient(ctx context.Context, realm Realm, clientID ClientID) error {
	urlStr := c.urlStr("admin", "realms", realm, "clients", clientID)
	req, err := c.newRequestJSON(http.MethodDelete, urlStr, nil)
	if err != nil {
		return err
	}
	return c.doRequest(ctx, req, nil)
}

// GenerateNewClientSecret generates a new client secret for client ClientID.
func (c *RESTClient) GenerateNewClientSecret(ctx context.Context, realm Realm, clientID ClientID) (*CredentialRepresentation, error) {
	urlStr := c.urlStr("admin", "realms", realm, "clients", clientID, "client-secret")
	req, err := c.newRequest(http.MethodPost, urlStr, nil, nil)
	if err != nil {
		return nil, err
	}
	var credentialRepresentation CredentialRepresentation
	if err := c.doRequest(ctx, req, &credentialRepresentation); err != nil {
		return nil, err
	}
	return &credentialRepresentation, nil
}

// Group returns the group groupID in realm.
func (c *RESTClient) Group(ctx context.Context, realm Realm, groupID GroupID) (*GroupRepresentation, error) {
	urlStr := c.urlStr("admin", "realms", realm, "groups", groupID)
	req, err := c.newRequest(http.MethodGet, urlStr, nil, nil)
	if err != nil {
		return nil, err
	}
	var groupRepresentation GroupRepresentation
	if err := c.doRequest(ctx, req, &groupRepresentation); err != nil {
		return nil, err
	}
	return &groupRepresentation, nil
}

// Groups returns a slice of groups, filtered according to the query options in
// groupsQuery.
func (c *RESTClient) Groups(ctx context.Context, realm Realm, groupsQuery *GroupsQuery) ([]*PartialGroupRepresentation, error) {
	urlStr := c.urlStr("admin", "realms", realm, "groups")
	req, err := c.newRequest(http.MethodGet, urlStr, groupsQuery.values(), nil)
	if err != nil {
		return nil, err
	}
	var pgrs []*PartialGroupRepresentation
	if err := c.doRequest(ctx, req, &pgrs); err != nil {
		return nil, err
	}
	return pgrs, nil
}

// UpdateClient creates a new client in realm.
func (c *RESTClient) UpdateClient(ctx context.Context, realm Realm, client *ClientRepresentation) error {
	urlStr := c.urlStr("admin", "realms", realm, "clients", client.ID)
	req, err := c.newRequestJSON(http.MethodPut, urlStr, client)
	if err != nil {
		return err
	}
	return c.doRequest(ctx, req, nil)
}

// User returns the user userID in realm.
func (c *RESTClient) User(ctx context.Context, realm Realm, userID UserID) (*UserRepresentation, error) {
	urlStr := c.urlStr("admin", "realms", realm, "users", userID)
	req, err := c.newRequest(http.MethodGet, urlStr, nil, nil)
	if err != nil {
		return nil, err
	}
	var userRepresentation UserRepresentation
	if err := c.doRequest(ctx, req, &userRepresentation); err != nil {
		return nil, err
	}
	return &userRepresentation, nil
}

// UserAddGroup adds userID to groupID in realm.
func (c *RESTClient) UserAddGroup(ctx context.Context, realm Realm, userID UserID, groupID GroupID) error {
	urlStr := c.urlStr("admin", "realms", realm, "users", userID, "groups", groupID)
	req, err := c.newRequest(http.MethodPut, urlStr, nil, nil)
	if err != nil {
		return err
	}
	return c.doRequest(ctx, req, nil)
}

// UserGroups returns the user userID in realm.
func (c *RESTClient) UserGroups(ctx context.Context, realm Realm, userID UserID) ([]GroupRepresentation, error) {
	urlStr := c.urlStr("admin", "realms", realm, "users", userID, "groups")
	req, err := c.newRequest(http.MethodGet, urlStr, nil, nil)
	if err != nil {
		return nil, err
	}
	var groupRepresentations []GroupRepresentation
	if err := c.doRequest(ctx, req, &groupRepresentations); err != nil {
		return nil, err
	}
	return groupRepresentations, nil
}

// UserRemoveGroup removes userID from groupID in realm.
func (c *RESTClient) UserRemoveGroup(ctx context.Context, realm Realm, userID UserID, groupID GroupID) error {
	urlStr := c.urlStr("admin", "realms", realm, "users", userID, "groups", groupID)
	req, err := c.newRequest(http.MethodDelete, urlStr, nil, nil)
	if err != nil {
		return err
	}
	return c.doRequest(ctx, req, nil)
}

// Users returns a slice of users, filtered according to the query options in
// userQuery.
func (c *RESTClient) Users(ctx context.Context, realm Realm, usersQuery *UsersQuery) ([]*PartialUserRepresentation, error) {
	urlStr := c.urlStr("admin", "realms", realm, "users")
	req, err := c.newRequest(http.MethodGet, urlStr, usersQuery.values(), nil)
	if err != nil {
		return nil, err
	}
	var purs []*PartialUserRepresentation
	if err := c.doRequest(ctx, req, &purs); err != nil {
		return nil, err
	}
	return purs, nil
}

// doCreateRequest performs req and extracts the id of the newly-created
// resource from the response's Location header.
func (c *RESTClient) doCreateRequest(ctx context.Context, req *http.Request) (string, error) {
	req = req.WithContext(ctx)
	httpClient := c.config.Client(ctx)
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || http.StatusMultipleChoices <= resp.StatusCode {
		respBody, _ := ioutil.ReadAll(resp.Body)
		return "", &RESTError{
			Request:      req,
			Response:     resp,
			ResponseBody: respBody,
		}
	}
	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		return "", err
	}
	return path.Base(location.Path), nil
}

// doRequest performs req and optionally unmarshals the JSON response.
func (c *RESTClient) doRequest(ctx context.Context, req *http.Request, v interface{}) error {
	if v != nil {
		req.Header.Set("Accept", "application/json")
	}
	req = req.WithContext(ctx)
	httpClient := c.config.Client(ctx)
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || http.StatusMultipleChoices <= resp.StatusCode {
		respBody, _ := ioutil.ReadAll(resp.Body)
		return &RESTError{
			Request:      req,
			Response:     resp,
			ResponseBody: respBody,
		}
	}
	if v != nil {
		if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
			return err
		}
	}
	return nil
}

// newRequest creats a new http.Request.
func (c *RESTClient) newRequest(method, urlStr string, values url.Values, body io.Reader) (*http.Request, error) {
	if values != nil {
		urlStr += "?" + values.Encode()
	}
	return http.NewRequest(method, urlStr, body)
}

// newRequestJSON creates a new http.Request with a JSON body.
func (c *RESTClient) newRequestJSON(method, urlStr string, body interface{}) (*http.Request, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := c.newRequest(method, urlStr, nil, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

// urlStr returns the URL for the resource defined by pathElements.
func (c *RESTClient) urlStr(pathElements ...interface{}) string {
	es := make([]string, 0, len(pathElements))
	for _, pathElement := range pathElements {
		switch e := pathElement.(type) {
		case string:
			es = append(es, e)
		case ClientID:
			es = append(es, string(e))
		case GroupID:
			es = append(es, string(e))
		case Realm:
			es = append(es, string(e))
		case UserID:
			es = append(es, string(e))
		default:
			panic(fmt.Sprintf("unsupported path element type %T", e))
		}
	}
	return c.baseURL + "/" + path.Join(es...)
}

func (e *RESTError) Error() string {
	s := fmt.Sprintf("%s: %d %s", e.Request.URL, e.Response.StatusCode, http.StatusText(e.Response.StatusCode))
	if len(e.ResponseBody) != 0 {
		s += ": " + string(e.ResponseBody)
	}
	return s
}

// getTokenURLPathForRealm returns the path component of the token URL of realm.
func getTokenURLPathForRealm(realm Realm) string {
	return "/realms/" + string(realm) + "/protocol/openid-connect/token"
}

// values returns the url.Values for c.
func (c *ClientsQuery) values() url.Values {
	if c == nil {
		return nil
	}
	values := make(url.Values)
	valuesMaybeAddString(values, "clientId", c.ClientID)
	valuesMaybeAddBool(values, "viewableOnly", c.ViewableOnly)
	return values
}

// values returns the url.Values for g.
func (g *GroupsQuery) values() url.Values {
	if g == nil {
		return nil
	}
	values := make(url.Values)
	valuesMaybeAddInt(values, "first", g.First)
	valuesMaybeAddInt(values, "max", g.Max)
	valuesMaybeAddString(values, "search", g.Search)
	return values
}

// values returns the url.Values for u.
func (u *UsersQuery) values() url.Values {
	if u == nil {
		return nil
	}
	values := make(url.Values)
	valuesMaybeAddBool(values, "briefRepresentation", u.BriefRepresentation)
	valuesMaybeAddString(values, "email", u.Email)
	valuesMaybeAddInt(values, "first", u.First)
	valuesMaybeAddString(values, "firstName", u.FirstName)
	valuesMaybeAddString(values, "lastName", u.LastName)
	valuesMaybeAddInt(values, "max", u.Max)
	valuesMaybeAddString(values, "search", u.Search)
	valuesMaybeAddString(values, "username", u.Username)
	return values
}

// valuesMaybeAddBool adds b to values[key] if b is true.
func valuesMaybeAddBool(values url.Values, key string, b bool) {
	if b {
		values.Add(key, "true")
	}
}

// valuesMaybeAddInt adds i to values[key] if i is non-zero.
func valuesMaybeAddInt(values url.Values, key string, i int) {
	if i != 0 {
		values.Add(key, strconv.Itoa(i))
	}
}

// valuesMaybeAddString adds s to values[key] if s is not empty.
func valuesMaybeAddString(values url.Values, key string, s string) {
	if s != "" {
		values.Add(key, s)
	}
}
