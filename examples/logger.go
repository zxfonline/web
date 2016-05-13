package main

import (
	"github.com/zxfonline/golog"

	"github.com/zxfonline/web"
)

func hello(val string) string { return "hello " + val }

func main() {
	golog.InitConfig("./log4go.cfg")
	logger := golog.New("test")
	web.Get("/hello/(.*)", hello)
	web.Get("/close", func() {
		web.Close()
	})
	web.SetLogger(logger)
	web.Run("0.0.0.0:9999")
}
