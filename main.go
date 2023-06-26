package main

import (
	"flag"
	"fmt"
	"net/http"
)

func main() {
	addr := flag.String("addr", ":8080", "address to listen to")
	flag.Parse()

	http.HandleFunc("/", handleRoot)
	http.HandleFunc("/start", handleStart)
	http.HandleFunc("/auth/callback", handleCallback)
	http.HandleFunc("/signed-in", handleSignedIn)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/refresh", handleRefresh)
	fmt.Println("Hello")
	panic(http.ListenAndServe(*addr, nil))
}
