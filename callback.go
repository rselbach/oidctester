package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

func handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cfg := getConfigFromCookie(r)

	provider, err := oidc.NewProvider(ctx, cfg.Root)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Ooops %v", err)
		return
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	oc := oauth2.Config{
		ClientID:    cfg.ClientID,
		Endpoint:    provider.Endpoint(),
		RedirectURL: fmt.Sprintf("%s://%s/auth/callback", scheme, r.Host),
		Scopes:      []string{oidc.ScopeOpenID, "offline", "offline_access"},
	}

	codeVerifierCookie, err := r.Cookie("code_verifier")
	if err != nil {
		httpError(w, http.StatusUnauthorized, "could not read code verifier cookie: %s", err)
		return
	}

	cv := codeVerifier(codeVerifierCookie.Value)

	code := r.FormValue("code")

	log.Println("verif", codeVerifierCookie.Value, len(codeVerifierCookie.Value))
	token, err := oc.Exchange(ctx, code, cv.Verifier())
	if err != nil {
		httpError(w, http.StatusUnauthorized, "could not exchange token: %s", err)
		return
	}

	idToken, _ := token.Extra("id_token").(string)

	sc := stateCookie{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		IDToken:      idToken,
	}
	sc.save(w)
	http.Redirect(w, r, "/signed-in", http.StatusFound)
}

func httpError(w http.ResponseWriter, code int, templ string, a ...any) {
	e := fmt.Sprintf(templ, a...)
	http.Error(w, e, code)
}
