package main

import (
	"fmt"
	"time"

	"github.com/zxfonline/httplib"

	"errors"

	trace "github.com/zxfonline/golangtrace"
	"github.com/zxfonline/web"
)

func main() {
	web.CopyRequestBody = true
	web.Get("/json", func(ctx *web.Context) string {
		tr := trace.New("mypkg.json", ctx.Request.URL.Path, false)
		defer tr.Finish()

		str := string(ctx.RequestBody)
		fmt.Println("name:", ctx.ParamStr("name"))
		fmt.Println("rec:", str)

		tr.LazyPrintf("some event %q happened", str)
		if ctx.ParamStr("name") != "zxf" {
			tr.LazyPrintf("somethingImportant failed: %v", errors.New("no,error!"))
			tr.SetError()
		}
		return str
	})
	web.Get("/close", func() {
		web.Close()
	})
	go func() {
		time.Sleep(1 * time.Second)
		req := httplib.Get("http://127.0.0.1:9999/json?name=zxf")
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
