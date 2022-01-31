package auth

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/txsvc/stdlib/pkg/timestamp"
)

const (
	// AuthTypeBearerToken constant token
	AuthTypeBearerToken = "token"
	// AuthTypeJWT constant jwt
	AuthTypeJWT = "jwt"
	// AuthTypeSlack constant slack
	AuthTypeSlack = "slack"

	// other defaults
	UserTokenType    = "user"
	AppTokenType     = "app"
	APITokenType     = "api"
	BotTokenType     = "bot"
	DefaultTokenType = UserTokenType

	// default scopes
	ScopeRead    = "api:read"
	ScopeWrite   = "api:write"
	ScopeAdmin   = "api:admin"
	DefaultScope = "api:read api:write"
)

type (
	// Authorization represents a user, app or bot and its permissions
	Authorization struct {
		ClientID  string `json:"client_id" binding:"required"` // UNIQUE
		Realm     string `json:"realm"`
		Token     string `json:"token" binding:"required"`
		TokenType string `json:"token_type" binding:"required"` // e.g. user,app,api,bot
		UserID    string `json:"user_id"`                       // depends on TokenType. E.g. email, ClientID or BotUserID(Slack)
		Scope     string `json:"scope"`                         // a comma separated list of scopes, see below
		Expires   int64  `json:"expires"`                       // 0 = never
		// internal
		Revoked bool  `json:"-"`
		Created int64 `json:"-"`
		Updated int64 `json:"-"`
	}

	// AuthorizationRequest represents a login/authorization request from a user, app, or bot
	AuthorizationRequest struct {
		Realm    string `json:"realm" binding:"required"`
		UserID   string `json:"user_id" binding:"required"`
		ClientID string `json:"client_id"`
		Token    string `json:"token"`
		Scope    string `json:"scope"`
	}
)

var (
	// ErrNotAuthorized indicates that the API caller is not authorized
	ErrNotAuthorized     = errors.New("not authorized")
	ErrAlreadyAuthorized = errors.New("already authorized")

	// ErrNoSuchEntity indicates that the authorization does not exist
	ErrNoSuchEntity = errors.New("entity does not exist")

	// ErrNoToken indicates that no bearer token was provided
	ErrNoToken = errors.New("no token provided")
	// ErrNoScope indicates that no scope was provided
	ErrNoScope = errors.New("no scope provided")

	// different types of lookup tables
	tokenToAuth map[string]*Authorization
	idToAuth    map[string]*Authorization
)

func init() {
	tokenToAuth = make(map[string]*Authorization)
	idToAuth = make(map[string]*Authorization)
}

func (auth *Authorization) Equal(a *Authorization) bool {
	if a == nil {
		return false
	}
	return auth.Token == a.Token && auth.Realm == a.Realm && auth.ClientID == a.ClientID && auth.UserID == a.UserID
}

func (auth *Authorization) String() string {
	return fmt.Sprintf("%s,%s,%s,%s,%s,%s,%d", auth.ClientID, auth.Realm, auth.Token, auth.TokenType, auth.UserID, auth.Scope, auth.Expires)
}

// IsValid verifies that the Authorization is still valid, i.e. is not expired and not revoked.
func (auth *Authorization) IsValid() bool {
	if auth.Revoked {
		return false
	}
	if auth.Expires == 0 {
		return true
	} else if auth.Expires < timestamp.Now() {
		return false
	}
	return true
}

// HasAdminScope checks if the authorization includes scope 'api:admin'
func (auth *Authorization) HasAdminScope() bool {
	return strings.Contains(auth.Scope, ScopeAdmin)
}

// FindAuthorizationByToken looks for an authorization by the token
func FindAuthorizationByToken(ctx context.Context, token string) (*Authorization, error) {
	if token == "" {
		return nil, ErrNoToken
	}
	if a, ok := tokenToAuth[token]; ok {
		return a, nil
	}
	return nil, nil
}

func NewAuthorization(req *AuthorizationRequest, expires int) *Authorization {
	now := timestamp.Now()

	a := Authorization{
		ClientID:  req.ClientID,
		Realm:     req.Realm,
		Token:     CreateSimpleToken(),
		TokenType: DefaultTokenType,
		UserID:    req.UserID,
		Scope:     req.Scope,
		Revoked:   false,
		Expires:   now + int64(expires*86400),
		Created:   now,
		Updated:   now,
	}
	if expires == 0 {
		a.Expires = 0
	}

	return &a
}

func RegisterAuthorization(auth *Authorization) {
	tokenToAuth[auth.Token] = auth
	idToAuth[namedKey(auth.Realm, auth.ClientID)] = auth
}

// LookupAuthorization looks for an authorization
func LookupAuthorization(ctx context.Context, realm, clientID string) (*Authorization, error) {
	if a, ok := idToAuth[namedKey(realm, clientID)]; ok {
		return a, nil
	}
	return nil, nil
}

func DeleteAuthorization(ctx context.Context, realm, clientID string) (*Authorization, error) {
	return nil, fmt.Errorf("not implemented")
}

func parse(s string) (*Authorization, error) {
	if s == "" {
		return nil, ErrNoSuchEntity
	}
	parts := strings.Split(s, ",")
	if len(parts) != 7 {
		return nil, ErrNoSuchEntity
	}
	now := timestamp.Now()
	a := Authorization{
		ClientID:  parts[0],
		Realm:     parts[1],
		Token:     parts[2],
		TokenType: parts[3],
		UserID:    parts[4],
		Scope:     parts[5],
		Revoked:   false,
		Expires:   0,
		Created:   now,
		Updated:   now,
	}
	n, err := strconv.ParseInt(parts[6], 10, 64)
	if err != nil {
		return nil, err
	}
	a.Expires = n

	return &a, nil
}

// return fmt.Sprintf("%s,%s,%s,%s,%s,%s,%d", auth.ClientID, auth.Realm, auth.Token, auth.TokenType, auth.UserID, auth.Scope, auth.Expires)

func hasScope(scopes, scope string) bool {
	// FIXME this is a VERY simple implementation
	if scopes == "" || scope == "" {
		return false // empty inputs should never evalute to true
	}

	// FIXME this is a VERY naiv implementation
	return strings.Contains(scopes, scope)
}

func namedKey(part1, part2 string) string {
	return part1 + "." + part2
}
