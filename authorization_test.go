package auth

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/txsvc/stdlib/pkg/timestamp"
)

const (
	realm    = "realm"
	userID   = "userid"
	clientID = "client@example.com"

	scopeProductionRead  = "production:read"
	scopeProductionWrite = "production:write"
	scopeProductionBuild = "production:build"
	scopeResourceRead    = "resource:read"
	scopeResourceWrite   = "resource:write"

	// one element is missig
	invalidString1 = "client@example.com,realm,cdeba542-ebb0-4cae-9544-df6059ba1752,user,api:read api:write,1637152046"
	// expires is not a number
	invalidString2 = "client@example.com,realm,cdeba542-ebb0-4cae-9544-df6059ba1752,user,userid,api:read api:write,nonumber"
)

func TestScope(t *testing.T) {

	scope1 := "production:read,production:write,production:build"

	assert.False(t, hasScope("", ""))
	assert.False(t, hasScope(scope1, ""))
	assert.False(t, hasScope("", scopeResourceRead))

	assert.True(t, hasScope(scope1, scopeProductionRead))
	assert.False(t, hasScope(scope1, scopeResourceRead))
}

func TestNewAuthorization(t *testing.T) {
	now := timestamp.Now()

	req := AuthorizationRequest{
		Realm:    realm,
		UserID:   userID,
		ClientID: clientID,
		Scope:    DefaultScope,
	}
	auth := NewAuthorization(&req, 1)
	assert.NotNil(t, auth)

	assert.Equal(t, req.Realm, auth.Realm)
	assert.Equal(t, req.UserID, auth.UserID)
	assert.Equal(t, req.ClientID, auth.ClientID)
	assert.Equal(t, req.Scope, auth.Scope)
	assert.NotEmpty(t, auth.Token)
	assert.Equal(t, DefaultTokenType, auth.TokenType)
	assert.Greater(t, auth.Expires, now)
	assert.True(t, auth.IsValid())

	// expired
	auth = NewAuthorization(&req, -1)
	assert.NotNil(t, auth)
	assert.False(t, auth.IsValid())

	// no expiration
	auth = NewAuthorization(&req, 0)
	assert.NotNil(t, auth)
	assert.True(t, auth.IsValid())
}

func TestAdminScope(t *testing.T) {

	req := AuthorizationRequest{
		Realm:    realm,
		UserID:   userID,
		ClientID: clientID,
		Scope:    DefaultScope,
	}
	auth := NewAuthorization(&req, 1)
	assert.False(t, auth.HasAdminScope())

	req.Scope = scopeProductionRead + " " + ScopeAdmin
	auth = NewAuthorization(&req, 1)
	assert.True(t, auth.HasAdminScope())
}

func TestToString(t *testing.T) {
	req := AuthorizationRequest{
		Realm:    realm,
		UserID:   userID,
		ClientID: clientID,
		Scope:    DefaultScope,
	}
	auth := NewAuthorization(&req, 1)

	s := auth.String()
	assert.NotEmpty(t, s)

	fmt.Println(s)
	parts := strings.Split(s, ",")
	assert.Equal(t, 7, len(parts))
}

func TestParseString(t *testing.T) {
	req := AuthorizationRequest{
		Realm:    realm,
		UserID:   userID,
		ClientID: clientID,
		Scope:    DefaultScope,
	}
	auth := NewAuthorization(&req, 1)

	s := auth.String()
	assert.NotEmpty(t, s)

	auth2, err := parse(s)
	assert.NotNil(t, auth2)
	assert.NoError(t, err)

	assert.Equal(t, auth.Realm, auth2.Realm)
	assert.Equal(t, auth.UserID, auth2.UserID)
	assert.Equal(t, auth.ClientID, auth2.ClientID)
	assert.Equal(t, auth.Scope, auth2.Scope)
	assert.Equal(t, auth.Token, auth2.Token)
	assert.Equal(t, auth.TokenType, auth2.TokenType)
	assert.Equal(t, auth.Expires, auth2.Expires)
	assert.True(t, auth2.IsValid())
}

func TestParseStringError(t *testing.T) {
	auth, err := parse(invalidString1)
	assert.Nil(t, auth)
	assert.Error(t, err)

	auth, err = parse(invalidString2)
	assert.Nil(t, auth)
	assert.Error(t, err)
}
