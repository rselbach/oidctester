package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

func handleStart(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	cfg := config{
		Root:         r.PostFormValue("server-root"),
		ClientID:     r.PostFormValue("client-id"),
		ClientSecret: r.PostFormValue("client-secret"),
	}

	// We'll want to save this as a cookie.
	if err := saveConfigAsCookie(w, cfg); err != nil {
		log.Printf("could not save cookie: %s", err)
	}

	ctx := r.Context()
	provider, err := oidc.NewProvider(ctx, cfg.Root)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Ooops %v", err)
		return
	}
	oc := oauth2.Config{
		ClientID:    cfg.ClientID,
		Endpoint:    provider.Endpoint(),
		RedirectURL: "http://localhost:8080/auth/callback",
		Scopes:      []string{oidc.ScopeOpenID, "offline", "offline_access"},
	}

	cv, _ := generateCodeVerifier()
	state := nonce() // This should be a random string for security purposes

	//http.SetCookie(w, &http.Cookie{Name: "state", Value: state, Path: "/"})
	http.SetCookie(w, &http.Cookie{Name: "code_verifier", Value: string(cv), Path: "/"})

	authURL := oc.AuthCodeURL(state, oauth2.AccessTypeOnline,
		cv.Challenge(),
		cv.Method())

	http.Redirect(w, r, authURL, http.StatusFound)
}
