package auth

import (
	"context"
	"net/http"

	"github.com/labstack/echo/v4"
)

// CheckAuthorization relies on the presence of a bearer token and validates the
// matching authorization against a list of requested scopes. If everything checks
// out, the function returns the authorization or an error otherwise.
func CheckAuthorization(ctx context.Context, c echo.Context, scope string) (*Authorization, error) {
	token, err := GetBearerToken(c.Request())
	if err != nil {
		return nil, err
	}

	auth, err := FindAuthorizationByToken(ctx, token)
	if err != nil || auth == nil || !auth.IsValid() {
		return nil, ErrNotAuthorized
	}

	if auth.HasAdminScope() {
		return auth, nil
	}

	if !hasScope(auth.Scope, scope) {
		return nil, ErrNotAuthorized
	}

	return auth, nil
}

// GetClientID extracts the ClientID from the token
func GetClientID(ctx context.Context, r *http.Request) (string, error) {
	token, err := GetBearerToken(r)
	if err != nil {
		return "", err
	}

	// FIXME optimize this, e.g. implement caching

	auth, err := FindAuthorizationByToken(ctx, token)
	if err != nil {
		return "", err
	}
	if auth == nil {
		return "", ErrNotAuthorized
	}

	return auth.ClientID, nil
}
