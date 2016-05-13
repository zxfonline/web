package main

import (
	"github.com/zxfonline/web"
)

func hello1(val string) string { return "hello1 " + val }

func hello2(val string) string { return "hello2 " + val }

func main() {
	var server1 web.Server
	var server2 web.Server

	server1.Get("/hello/(.*)", hello1)
	server1.Get("/close", func() {
		server1.Close()
	})
	go server1.Run("0.0.0.0:9999")
	server2.Get("/hello/(.*)", hello2)
	server2.Get("/close", func() {
		server2.Close()
	})
	go server2.Run("0.0.0.0:8999")
	<-make(chan int)
}
