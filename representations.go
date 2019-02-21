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

const (
	// DecisionStrategyAffirmative is the affirmative decision strategy.
	DecisionStrategyAffirmative DecisionStrategy = "AFFIRMATIVE"
	// DecisionStrategyUnanimous is the unanimous decision strategy.
	DecisionStrategyUnanimous DecisionStrategy = "UNANIMOUS"
	// DecisionStrategyConsensus is the consensus decision strategy.
	DecisionStrategyConsensus DecisionStrategy = "CONSENSUS"

	// PolicyEnforcementModeEnforcing is the enforcing policy enforcement mode.`
	PolicyEnforcementModeEnforcing PolicyEnforcementMode = "ENFORCING"
	// PolicyEnforcementModePermissive is the permissive policy enforcement mode.
	PolicyEnforcementModePermissive PolicyEnforcementMode = "PERMISSIVE"
	// PolicyEnforcementModeDisabled is the disabled policy enforcement mode.
	PolicyEnforcementModeDisabled PolicyEnforcementMode = "DISABLED"

	// LogicPositive is positive logic.
	LogicPositive Logic = "POSITIVE"
	// LogicNegative is negative logic.
	LogicNegative Logic = "NEGATIVE"
)

// A ClientID is a client ID.
type ClientID string

// A ContainerID is a container ID.
type ContainerID string

// A GroupID is a group ID.
type GroupID string

// A PolicyRepresentationID is a policy representation ID.
type PolicyRepresentationID string

// A ProtocolMapperRepresentationID is a protocol mapper representation ID.
type ProtocolMapperRepresentationID string

// A Realm is a realm.
type Realm string

// A ResourceRepresentationID is a resource representation ID.
type ResourceRepresentationID string

// A ResourceServerRepresentationID is a resource server representation ID.
type ResourceServerRepresentationID string

// A RoleID is a role ID.
type RoleID string

// A ScopeRepresentationID is a scope representation ID.
type ScopeRepresentationID string

// A UserID is a user ID.
type UserID string

// A DecisionStrategy is a decision strategy.
type DecisionStrategy string

// A Logic is a logic.
type Logic string

// A PolicyEnforcementMode is a policy enforcement mode.
type PolicyEnforcementMode string

// A MultivaluedHashMap is map with multiple values for each key.
// FIXME compare with https://github.com/Azuka/keycloak-admin-go/blob/master/keycloak/types.go#L39-L45
type MultivaluedHashMap map[string][]interface{}

// A ClientRepresentation is Keycloak's representation of a Client.
type ClientRepresentation struct {
	Access                             map[string]interface{}          `json:"access,omitempty"`
	AdminURL                           string                          `json:"adminUrl,omitempty"`
	Attributes                         map[string][]string             `json:"attributes,omitempty"`
	AuthenticationFlowBindingOverrides map[string]interface{}          `json:"authenticationFlowBindingOverrides,omitempty"`
	AuthorizationServicesEnabled       bool                            `json:"authorizationServicesEnabled,omitempty"`
	AuthorizationSettings              *ResourceServerRepresentation   `json:"authorizationSettings,omitempty"`
	BaseURL                            string                          `json:"baseUrl,omitempty"`
	BearerOnly                         bool                            `json:"bearerOnly,omitempty"`
	ClientAuthenticatorType            string                          `json:"clientAuthenticatorType,omitempty"`
	ClientID                           ClientID                        `json:"clientId,omitempty"`
	ConsentRequired                    bool                            `json:"consentRequired,omitempty"`
	DefaultClientScopes                []string                        `json:"defaultClientScopes,omitempty"`
	DefaultRoles                       []string                        `json:"defaultRoles,omitempty"`
	Description                        string                          `json:"description,omitempty"`
	DirectAccessGrantsEnabled          bool                            `json:"directAccessGrantsEnabled,omitempty"`
	Enabled                            bool                            `json:"enabled,omitempty"`
	FrontchannelLogout                 bool                            `json:"frontchannelLogout,omitempty"`
	FullScopeAllowed                   bool                            `json:"fullScopeAllowed,omitempty"`
	ID                                 ClientID                        `json:"id,omitempty"`
	ImplicitFlowEnabled                bool                            `json:"implicitFlowEnabled,omitempty"`
	Name                               string                          `json:"name,omitempty"`
	NodeReRegistrationTimeout          int64                           `json:"nodeReRegistrationTimeout,omitempty"`
	NotBefore                          int64                           `json:"notBefore,omitempty"`
	ClientScopes                       []string                        `json:"clientScopes,omitempty"`
	Origin                             string                          `json:"origin,omitempty"`
	Protocol                           string                          `json:"protocol,omitempty"`
	ProtocolMappers                    []*ProtocolMapperRepresentation `json:"protocolMappers,omitempty"`
	PublicClient                       bool                            `json:"publicClient,omitempty"`
	RedirectURIs                       []string                        `json:"redirectUris,omitempty"`
	RegisteredNodes                    map[string]interface{}          `json:"registeredNodes,omitempty"`
	RegistrationAccessToken            string                          `json:"registrationAccessToken,omitempty"`
	RootURL                            string                          `json:"rootUrl,omitempty"`
	Secret                             string                          `json:"secret,omitempty"`
	ServiceAccountsEnabled             bool                            `json:"serviceAccountsEnabled,omitempty"`
	StandardFlowEnabled                bool                            `json:"standardFlowEnabled,omitempty"`
	SurrogateAuthRequired              bool                            `json:"surrogateAuthRequired,omitempty"`
	WebOrigins                         []string                        `json:"webOrigins,omitempty"`
}

// A CredentialRepresentation is Keycloak's representation of a Credential.
type CredentialRepresentation struct {
	Algorithm         string             `json:"algorithm,omitempty"`
	Config            MultivaluedHashMap `json:"config,omitempty"`
	Counter           int                `json:"counter,omitempty"`
	CreatedDate       int64              `json:"createdDate,omitempty"`
	Device            string             `json:"device,omitempty"`
	Digits            int                `json:"digits,omitempty"`
	HashIterations    int                `json:"hashIterations,omitempty"`
	HashedSaltedValue string             `json:"hashedSaltedValue,omitempty"`
	Period            int                `json:"period,omitempty"`
	Salt              string             `json:"salt,omitempty"`
	Temporary         bool               `json:"temporary,omitempty"`
	Type              string             `json:"type,omitempty"`
	Value             string             `json:"value,omitempty"`
}

// A GroupRepresentation is Keycloak's representation of a Group.
type GroupRepresentation struct {
	Access      map[string]interface{} `json:"access,omitempty"`
	Attributes  map[string][]string    `json:"attributes,omitempty"`
	ClientRoles map[string]interface{} `json:"clientRoles,omitempty"`
	ID          GroupID                `json:"id,omitempty"`
	Name        string                 `json:"name,omitempty"`
	Path        string                 `json:"path,omitempty"`
	RealmRoles  []string               `json:"realmRoles,omitempty"`
	SubGroups   []*GroupRepresentation `json:"subGroups,omitempty"`
}

// A FederatedIdentityRepresentation is Keycloak's representation of a
// FederatedIdentity.
type FederatedIdentityRepresentation struct {
	IdentityProvider string `json:"identityProvider,omitempty"`
	UserID           string `json:"userId,omitempty"`   // Federated, not a Keycloak UserID.
	UserName         string `json:"userName,omitempty"` // userName, not username.
}

// A ProtocolMapperRepresentation is Keycloak's representation of a
// ProtocolMapper.
type ProtocolMapperRepresentation struct {
	Config         map[string]interface{}         `json:"config,omitempty"`
	ID             ProtocolMapperRepresentationID `json:"id,omitempty"`
	Name           string                         `json:"name,omitempty"`
	Protocol       string                         `json:"protocol,omitempty"`
	ProtocolMapper string                         `json:"protocolMapper,omitempty"`
}

// A PolicyRepresentation is Keycloak's representation of a Policy.
type PolicyRepresentation struct {
	Config           map[string]interface{} `json:"config,omitempty"`
	DecisionStrategy DecisionStrategy       `json:"decisionStrategy,omitempty"`
	Description      string                 `json:"description,omitempty"`
	ID               PolicyRepresentationID `json:"id,omitempty"`
	Logic            Logic                  `json:"logic,omitempty"`
	Name             string                 `json:"name,omitempty"`
	Owner            string                 `json:"owner,omitempty"`
	Policies         []string               `json:"policies,omitempty"`
	Resources        []string               `json:"resources,omitempty"`
	Scopes           []string               `json:"scopes,omitempty"`
	Type             string                 `json:"type,omitempty"`
}

// A ResourceRepresentation is Keycloak's representation of a Resource.
type ResourceRepresentation struct {
	ID                 ResourceRepresentationID `json:"id,omitempty"`
	Attributes         map[string][]string      `json:"attributes,omitempty"`
	DisplayName        string                   `json:"displayName,omitempty"`
	IconURI            string                   `json:"icon_uri,omitempty"` // JSON icon_uri, not iconUri
	Name               string                   `json:"name,omitempty"`
	OwnerManagedAccess bool                     `json:"ownerManagedAccess,omitempty"`
	Scopes             []*ScopeRepresentation   `json:"scopes,omitempty"`
	Type               string                   `json:"type,omitempty"`
	URIs               []string                 `json:"uris,omitempty"`
}

// A ResourceServerRepresentation is Keycloak's representation of a
// ResourceServer.
type ResourceServerRepresentation struct {
	AllowRemoteResourceManagement bool                           `json:"allowRemoteResourceManagement,omitempty"`
	ClientID                      ClientID                       `json:"clientId,omitempty"`
	ID                            ResourceServerRepresentationID `json:"id,omitempty"`
	Name                          string                         `json:"name,omitempty"`
	Policies                      []*PolicyRepresentation        `json:"policies,omitempty"`
	PolicyEnforcementMode         PolicyEnforcementMode          `json:"policyEnforcementMode,omitempty"`
	Resources                     []*ResourceRepresentation      `json:"resources,omitempty"`
	Scopes                        []*ScopeRepresentation         `json:"scopes,omitempty"`
}

// A RoleRepresentation is Keycloak's representation of a Role.
type RoleRepresentation struct {
	Attributes  map[string][]string          `json:"attributes,omitempty"`
	ClientRole  bool                         `json:"clientRole,omitempty"`
	Composite   bool                         `json:"composite,omitempty"`
	Composites  RoleRepresentationComposites `json:"composites,omitempty"`
	ContainerID ContainerID                  `json:"containerId,omitempty"`
	Description string                       `json:"description,omitempty"`
	ID          RoleID                       `json:"id,omitempty"`
	Name        string                       `json:"name,omitempty"`
}

// A RoleRepresentationComposites is Keycloak's representation of a
// RoleRepresentation Composites.
type RoleRepresentationComposites struct {
	Client map[string][]string `json:"client,omitempty"`
	Realm  []Realm             `json:"realm,omitempty"`
}

// A ScopeRepresentation is Keycloak's representation of a Scope.
type ScopeRepresentation struct {
	DisplayName string                    `json:"displayName,omitempty"`
	IconURI     string                    `json:"iconUri,omitempty"`
	ID          ScopeRepresentationID     `json:"id,omitempty"`
	Name        string                    `json:"name,omitempty"`
	Policies    []*PolicyRepresentation   `json:"policies,omitempty"`
	Resources   []*ResourceRepresentation `json:"resources,omitempty"`
}

// A UserConsentRepresentation is Keycloak's representation of a UserConsent.
type UserConsentRepresentation struct {
	ClientID            ClientID `json:"clientId,omitempty"`
	CreatedDate         int64    `json:"createdDate,omitempty"`
	GrantedClientScopes []string `json:"grantedClientScopes,omitempty"`
	LastUpdatedDate     int64    `json:"lastUpdatedDate,omitempty"`
}

// A UserRepresentation is Keycloak's representation of a User.
type UserRepresentation struct {
	Access                     map[string]interface{}             `json:"access,omitempty"`
	Attributes                 map[string][]string                `json:"attributes,omitempty"`
	ClientConsents             []*UserConsentRepresentation       `json:"clientConsents,omitempty"`
	ClientRoles                map[string]interface{}             `json:"clientRoles,omitempty"`
	CreatedTimestamp           int64                              `json:"createdTimestamp,omitempty"`
	Credentials                []*CredentialRepresentation        `json:"credentials,omitempty"`
	DisableableCredentialTypes []string                           `json:"disableableCredentialTypes,omitempty"`
	Email                      string                             `json:"email,omitempty"`
	EmailVerified              bool                               `json:"emailVerified,omitempty"`
	Enabled                    bool                               `json:"enabled,omitempty"`
	FederatedIdentities        []*FederatedIdentityRepresentation `json:"federatedIdentities,omitempty"`
	FederationLink             string                             `json:"federationLink,omitempty"`
	FirstName                  string                             `json:"firstName,omitempty"`
	Groups                     []string                           `json:"groups,omitempty"`
	ID                         UserID                             `json:"id,omitempty"`
	LastName                   string                             `json:"lastName,omitempty"`
	NotBefore                  int64                              `json:"notBefore,omitempty"`
	Origin                     string                             `json:"origin,omitempty"`
	RealmRoles                 []string                           `json:"realmRoles,omitempty"`
	RequiredActions            []string                           `json:"requiredActions,omitempty"`
	Self                       string                             `json:"self,omitempty"`
	ServiceAccountClientID     ClientID                           `json:"serviceAccountClientId,omitempty"`
	Username                   string                             `json:"username,omitempty"`
}

// A PartialClientRepresentation is a ClientRepresentation that is only
// partially complete.
type PartialClientRepresentation ClientRepresentation

// A PartialGroupRepresentation is a GroupRepresentation that is only partially
// complete.
type PartialGroupRepresentation GroupRepresentation

// A PartialUserRepresentation is a UserRepresentation that is only partially
// complete.
type PartialUserRepresentation UserRepresentation
