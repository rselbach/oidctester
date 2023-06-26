package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/oauth2"
)

// generateCodeVerifier generates a new random PKCE code.
func generateCodeVerifier() (codeVerifier, error) { return generate(rand.Reader) }

func generate(rand io.Reader) (codeVerifier, error) {
	// From https://tools.ietf.org/html/rfc7636#section-4.1:
	//   code_verifier = high-entropy cryptographic random STRING using the
	//   unreserved characters [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
	//   from Section 2.3 of [RFC3986], with a minimum length of 43 characters
	//   and a maximum length of 128 characters.
	var buf [32]byte
	if _, err := io.ReadFull(rand, buf[:]); err != nil {
		return "", fmt.Errorf("could not generate PKCE code: %w", err)
	}
	return codeVerifier(hex.EncodeToString(buf[:])), nil
}

// codeVerifier implements the basic options required for RFC 7636: Proof Key for codeVerifier Exchange (PKCE).
type codeVerifier string

// Challenge returns the OAuth2 auth code parameter for sending the PKCE code challenge.
func (p *codeVerifier) Challenge() oauth2.AuthCodeOption {
	b := sha256.Sum256([]byte(*p))
	return oauth2.SetAuthURLParam("code_challenge", base64.RawURLEncoding.EncodeToString(b[:]))
}

// Method returns the OAuth2 auth code parameter for sending the PKCE code challenge method.
func (p *codeVerifier) Method() oauth2.AuthCodeOption {
	return oauth2.SetAuthURLParam("code_challenge_method", "S256")
}

// Verifier returns the OAuth2 auth code parameter for sending the PKCE code verifier.
func (p *codeVerifier) Verifier() oauth2.AuthCodeOption {
	return oauth2.SetAuthURLParam("code_verifier", string(*p))
}
