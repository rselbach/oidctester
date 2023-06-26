package main

import (
	"embed"
	_ "embed"
	"html/template"
	"io"
)

//go:embed static/*
var content embed.FS

var templates = template.Must(
	template.ParseFS(content, "static/*.gohtml"),
)

func mustRoot(w io.Writer, server, clientID, clientSecret string) {
	err := templates.ExecuteTemplate(w, "root.gohtml", map[string]interface{}{
		"server":       server,
		"clientID":     clientID,
		"clientSecret": clientSecret,
	})
	if err != nil {
		panic(err)
	}
}

func mustSignedIn(w io.Writer, sc stateCookie) {
	err := templates.ExecuteTemplate(w, "signed-in.gohtml", map[string]interface{}{
		"accessToken":        sc.AccessToken,
		"accessTokenPayload": parseToken(sc.AccessToken),
		"refreshToken":       sc.RefreshToken,
		"idToken":            sc.IDToken,
		"idTokenPayload":     parseToken(sc.IDToken),
	})
	if err != nil {
		panic(err)
	}
}
