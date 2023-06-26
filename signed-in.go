package main

import (
	"net/http"
)

func handleSignedIn(w http.ResponseWriter, r *http.Request) {
	state, err := getState(r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	mustSignedIn(w, *state)
}
