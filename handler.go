package main

import (
	"net/http"
)

type config struct {
	Root         string
	ClientID     string
	ClientSecret string
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	if _, err := getState(r); err == nil {
		http.Redirect(w, r, "/signed-in", http.StatusFound)
		return
	}

	cfg := getConfigFromCookie(r)

	mustRoot(w, cfg.Root, cfg.ClientID, cfg.ClientSecret)
}
