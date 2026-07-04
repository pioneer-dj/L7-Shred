package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func SetupRoutes() *mux.Router {
	r := mux.NewRouter()

	api := r.PathPrefix("/api").Subrouter()

	api.HandleFunc("/register", RegisterHandler).Methods(http.MethodPost)
	api.HandleFunc("/login", LoginHandler).Methods(http.MethodPost)
	api.HandleFunc("/refresh", RefreshHandler).Methods(http.MethodPost)
	api.HandleFunc("/logout", LogoutHandler).Methods(http.MethodPost)

	api.HandleFunc("/me", AuthMiddleware(MeHandler)).Methods(http.MethodGet)
	api.HandleFunc("/update-name", AuthMiddleware(UpdateNameHandler)).Methods(http.MethodPut)
	api.HandleFunc("/update-password", AuthMiddleware(UpdatePasswordHandler)).Methods(http.MethodPut)
	api.HandleFunc("/delete-account", AuthMiddleware(DeleteAccountHandler)).Methods(http.MethodDelete)

	return r
}