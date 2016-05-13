package main

import (
	"github.com/zxfonline/web"
)

func hello(val string) string { return "hello " + val }

func main() {
	web.Get("/hello/(.*)", hello)
	web.Get("/close", func() {
		web.Close()
	})
	web.Run("0.0.0.0:9999")
}
