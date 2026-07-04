package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/l7-shred/core/internal/auth"
)

type contextKey string

const UserContextKey contextKey = "user"

func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			sendJSONError(w, "missing authorization header", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			sendJSONError(w, "invalid authorization header format", http.StatusUnauthorized)
			return
		}

		claims, err := auth.ValidateAccessToken(parts[1])
		if err != nil {
			sendJSONError(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), UserContextKey, claims)
		next(w, r.WithContext(ctx))
	}
}

func sendJSONError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}