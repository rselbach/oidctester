package main

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

func parseToken(jwtString string) string {
	token, _, err := new(jwt.Parser).ParseUnverified(jwtString, jwt.MapClaims{})
	if err != nil {
		return err.Error()
	}

	var sb strings.Builder
	printJSON(&sb, token.Header)
	printJSON(&sb, token.Claims)

	return sb.String()
}

func printJSON(w io.Writer, v interface{}) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "   ")
	enc.Encode(v)
}
