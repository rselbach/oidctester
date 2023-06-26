package main

import (
	"net/http"
)

func handleLogout(w http.ResponseWriter, r *http.Request) {
	deleteState(w)
	http.Redirect(w, r, "/", http.StatusFound)
}
