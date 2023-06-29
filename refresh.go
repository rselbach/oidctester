package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

func handleRefresh(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cfg := getConfigFromCookie(r)

	provider, err := oidc.NewProvider(ctx, cfg.Root)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Ooops %v", err)
		return
	}

	state, err := getState(r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	payload := url.Values{}
	payload.Set("grant_type", "refresh_token")
	payload.Set("refresh_token", state.RefreshToken)
	payload.Set("client_id", cfg.ClientID)
	if cfg.ClientSecret != "" {
		payload.Set("client_secret", cfg.ClientSecret)
	}

	req, err := http.NewRequest(http.MethodPost, provider.Endpoint().TokenURL, strings.NewReader(payload.Encode()))
	if err != nil {
		httpError(w, http.StatusInternalServerError, "oh no: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		httpError(w, http.StatusServiceUnavailable, "could not request token refresh: %v", err)
		return
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bc, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			httpError(w, http.StatusInternalServerError, "could not read response body: %v", err)
			return
		}
		httpError(w, resp.StatusCode, string(bc))
		return
	}

	var tok oauth2.Token
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		httpError(w, http.StatusUnauthorized, "could not refresh token: %v", err)
		return
	}

	state.AccessToken = tok.AccessToken
	state.RefreshToken = tok.RefreshToken
	if it, ok := tok.Extra("id_token").(string); ok {
		state.IDToken = it
	}

	if err := state.save(w); err != nil {
		httpError(w, http.StatusInternalServerError, "could not save state: %v", err)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)

}
