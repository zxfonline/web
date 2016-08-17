package main

import (
	"fmt"
	"time"

	"github.com/zxfonline/httplib"

	"github.com/zxfonline/web"
)

func main() {
	web.CopyRequestBody = true
	web.Post("/json", func(ctx *web.Context) string {
		str := string(ctx.RequestBody)
		fmt.Println("name:", ctx.ParamStr("name"))
		fmt.Println("rec:", str)
		return str
	})
	web.Get("/close", func() {
		web.Close()
	})
	go func() {
		time.Sleep(1 * time.Second)
		req := httplib.Post("http://127.0.0.1:9999/json?name=zxf")
		_, err := req.JsonBody(struct {
			Key   string
			Value string
		}{"kn", "kv"})

		if err != nil {
			panic(err)
		}
		str, err := req.String()
		if err != nil {
			panic(err)
		}
		fmt.Println("ret=", str)
		time.Sleep(1 * time.Second)
	}()
	web.Run("0.0.0.0:9999")

}
