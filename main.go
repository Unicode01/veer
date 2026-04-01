package main

import "forward/internal/app"

// buildNonce is set via -ldflags to make each build produce a unique binary.
var buildNonce string

func main() {
	app.Main(buildNonce)
}
