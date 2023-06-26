package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
)

func getConfigFromCookie(r *http.Request) config {
	var cfg config
	c, err := r.Cookie("oidcconfig")
	if err != nil {
		log.Printf("could not read cookie: %s", err)
		return cfg
	}
	b, err := base64.StdEncoding.DecodeString(c.Value)
	if err != nil {
		log.Printf("could not decode cookie: %v", err)
		return cfg
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		log.Printf("could not unmarshal cookie: %v (val: %q)", err, c.Value)
		return cfg
	}
	return cfg
}

func saveConfigAsCookie(w http.ResponseWriter, cfg config) error {
	b, err := json.Marshal(&cfg)
	if err != nil {
		return err
	}

	v := base64.StdEncoding.EncodeToString(b)

	c := &http.Cookie{
		Name:    "oidcconfig",
		Value:   v,
		Path:    "/",
		Expires: time.Now().Add(365 * 24 * time.Hour),
	}
	http.SetCookie(w, c)
	return nil
}

type stateCookie struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
}

const (
	accessTokenCookie = "access_token"
	refreshCookie     = "refresh_token"
	idCookie          = "id_token"
)

func (sc stateCookie) save(w http.ResponseWriter) error {
	setCookie(w, accessTokenCookie, sc.AccessToken)
	setCookie(w, refreshCookie, sc.RefreshToken)
	setCookie(w, idCookie, sc.IDToken)
	return nil
}

func getState(r *http.Request) (*stateCookie, error) {
	sc := &stateCookie{
		AccessToken:  getCookie(r, accessTokenCookie),
		RefreshToken: getCookie(r, refreshCookie),
		IDToken:      getCookie(r, idCookie),
	}
	if sc.AccessToken == "" {
		return nil, errors.New("missing access token")
	}
	return sc, nil
}

func deleteState(w http.ResponseWriter) {
	setCookie(w, accessTokenCookie, "")
	setCookie(w, refreshCookie, "")
	setCookie(w, idCookie, "")
}

func nonce() string {
	return uuid.NewString() + "-" + uuid.NewString()
}

func setCookie(w http.ResponseWriter, name, value string) {
	c := http.Cookie{
		Name:  name,
		Value: value,
		Path:  "/",
	}
	if value != "" {
		c.Expires = time.Now().Add(2 * 24 * time.Hour)
	} else {
		c.MaxAge = 0
	}
	http.SetCookie(w, &c)
}

func getCookie(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		log.Printf("could not find cookie named %s: %v", name, err)
		return ""
	}
	return c.Value
}
