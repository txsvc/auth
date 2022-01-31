package auth

import (
	"net/http"
	"strings"

	"github.com/txsvc/stdlib/pkg/id"
)

func CreateSimpleID() string {
	id, _ := id.ShortUUID()
	return id
}

func CreateSimpleToken() string {
	token, _ := id.UUID()
	return token
}

// GetBearerToken extracts the bearer token
func GetBearerToken(r *http.Request) (string, error) {

	// FIXME optimize this !!

	auth := r.Header.Get("Authorization")
	if len(auth) == 0 {
		return "", ErrNoToken
	}

	parts := strings.Split(auth, " ")
	if len(parts) != 2 {
		return "", ErrNoToken
	}
	if parts[0] == "Bearer" {
		return parts[1], nil
	}

	return "", ErrNoToken
}
